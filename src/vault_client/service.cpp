#include "prompt_airlock/vault_client/service.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <utility>

#include "prompt_airlock/vault_client/process.hpp"

namespace prompt_airlock::vault_client {

using namespace std::chrono_literals;

core::ProtectionError to_protection_error(ErrorCode) noexcept {
    // 발급 실패는 원인과 관계없이 "발급 불가"다. 원인은 VaultScope::last_error 로 감사에만 남는다(ADR 0019).
    return core::ProtectionError::IssuerUnavailable;
}

core::RestoreError to_restore_error(ErrorCode c) noexcept {
    switch (c) {
        case ErrorCode::TokenNotFound:
        case ErrorCode::MalformedToken:
            return core::RestoreError::TokenNotFound;
        default:
            return core::RestoreError::ResolverUnavailable;
    }
}

// Vault 프로세스 하나와 그 연결 풀.
struct VaultScope::Generation {
    Generation(VaultProcess p, const ServiceOptions& o)
        : process(std::move(p)), options(o.connection), pool_size(std::max<std::size_t>(o.pool_size, 1)),
          lease_timeout(o.lease_timeout) {
        // 연결할 때 서버 pid 가 우리가 띄운 프로세스인지 확인한다(ADR 0003).
        options.stream.expected_server_pid = process.ready().pid;
    }

    ~Generation() {
        std::lock_guard lock(process_mutex);
        idle.clear();
        process.close_stdin();
        if (!process.wait_exit(1000ms)) {
            process.kill();
        }
    }

    Generation(const Generation&) = delete;
    Generation& operator=(const Generation&) = delete;

    [[nodiscard]] bool is_dead() const noexcept { return dead.load(); }

    // 연결을 빌려 연산 하나를 하고 돌려준다.
    template <class F>
    auto call(F&& f) -> decltype(f(std::declval<VaultConnection&>())) {
        using R = decltype(f(std::declval<VaultConnection&>()));
        auto conn = lease();
        if (!conn) {
            return R(std::unexpected(conn.error()));
        }
        auto result = f(*conn);
        give_back(std::move(*conn));
        return result;
    }

    Result<VaultConnection> lease() {
        std::unique_lock lock(mutex);
        if (!available.wait_for(lock, lease_timeout, [&] { return is_dead() || !idle.empty() || open < pool_size; })) {
            return fail(ErrorCode::PoolExhausted);
        }
        if (is_dead()) {
            return fail(ErrorCode::Disconnected);
        }
        if (!idle.empty()) {
            auto conn = std::move(idle.back());
            idle.pop_back();
            return conn;
        }
        ++open;
        lock.unlock();
        auto conn = VaultConnection::connect(process.ready().endpoint, process.ready().secret, options);
        if (!conn) {
            lock.lock();
            --open;
            lock.unlock();
            check_exited();
            available.notify_all();
        }
        return conn;
    }

    void give_back(VaultConnection conn) {
        const bool broken = conn.broken();
        {
            std::lock_guard lock(mutex);
            if (broken) {
                --open;
            } else {
                idle.push_back(std::move(conn));
            }
        }
        if (broken) {
            check_exited();
        }
        available.notify_all();
    }

    // 연결이 끊기거나 연결하지 못했을 때 부른다. 프로세스가 끝났으면(종료가 반영될 때까지 잠깐 기다림) 세대를
    // 죽은 것으로 표시한다. 풀 잠금 밖에서 기다려 다른 요청을 막지 않고, 프로세스 확인은 따로 잠근다.
    void check_exited() noexcept {
        std::lock_guard lock(process_mutex);
        if (!is_dead() && process.wait_exit(exit_grace)) {
            // lease 는 풀 잠금을 쥔 채 술어를 확인하고 잠든다. 같은 잠금 안에서 바꿔야 알림을 놓치지 않는다.
            // 잠금 순서는 process_mutex 다음 mutex 하나뿐이다(풀 잠금을 쥔 채 process_mutex 를 잡는 경로는 없다).
            {
                std::lock_guard pool(mutex);
                dead.store(true);
            }
            available.notify_all();
        }
    }

    static constexpr std::chrono::milliseconds exit_grace{500};

    VaultProcess process;
    ConnectionOptions options;
    std::size_t pool_size;
    std::chrono::milliseconds lease_timeout;
    std::mutex mutex;
    std::mutex process_mutex;  // VaultProcess 는 스레드 안전하지 않으므로 종료 확인을 한 번에 하나만
    std::condition_variable available;
    std::vector<VaultConnection> idle;
    std::size_t open = 0;
    std::atomic<bool> dead{false};
};

VaultScope::VaultScope(std::shared_ptr<Generation> generation, ScopeId id) noexcept
    : generation_(std::move(generation)), id_(id) {}

VaultScope::VaultScope(VaultScope&& o) noexcept
    : generation_(std::move(o.generation_)), id_(o.id_), last_error_(o.last_error_) {}

VaultScope::~VaultScope() {
    // 범위를 지운다. 실패해도 Vault 의 TTL 이 마지막으로 정리한다.
    if (generation_ && !generation_->is_dead()) {
        (void)generation_->call([&](VaultConnection& c) { return c.drop_scope(id_); });
    }
}

std::expected<core::Token, core::ProtectionError> VaultScope::issue(core::EntityType type, std::string_view value) {
    const auto label = core::token_label(type);
    if (!label) {
        return std::unexpected(core::ProtectionError::LabelMismatch);  // 차단 종류는 가명화하지 않는다
    }
    if (!generation_ || generation_->is_dead()) {
        last_error_ = ErrorCode::Disconnected;
        return std::unexpected(core::ProtectionError::IssuerUnavailable);
    }
    auto text = generation_->call([&](VaultConnection& c) { return c.create_token(id_, *label, value); });
    if (!text) {
        last_error_ = text.error().code;
        return std::unexpected(to_protection_error(text.error().code));
    }
    return core::parse_token(*text);
}

std::expected<core::SensitiveText, core::RestoreError> VaultScope::resolve(const core::Token& token) {
    if (!generation_ || generation_->is_dead()) {
        last_error_ = ErrorCode::Disconnected;
        return std::unexpected(core::RestoreError::ResolverUnavailable);
    }
    auto value = generation_->call([&](VaultConnection& c) { return c.resolve_exact(id_, token.text()); });
    if (!value) {
        last_error_ = value.error().code;
        return std::unexpected(to_restore_error(value.error().code));
    }
    return std::move(*value);
}

VaultService::VaultService(ServiceOptions options)
    : options_(std::move(options)), restart_delay_(options_.restart_min) {}

VaultService::~VaultService() = default;

Result<VaultScope> VaultService::open_scope() {
    std::shared_ptr<VaultScope::Generation> generation;
    {
        std::lock_guard lock(mutex_);
        if (!current_ || current_->is_dead()) {
            const auto now = std::chrono::steady_clock::now();
            if (now < next_spawn_) {
                return fail(ErrorCode::RestartPending);
            }
            // 이번에 띄운 세대가 범위를 하나도 열지 못하고 죽으면 다음 간격은 두 배가 된다.
            next_spawn_ = now + restart_delay_;
            restart_delay_ = std::min(restart_delay_ * 2, options_.restart_max);
            current_.reset();
            auto process = VaultProcess::spawn({options_.exe, options_.args, options_.ready_timeout});
            if (!process) {
                return std::unexpected(process.error());
            }
            current_ = std::make_shared<VaultScope::Generation>(std::move(*process), options_);
        }
        generation = current_;
    }
    auto id = generation->call([&](VaultConnection& c) { return c.create_scope(options_.scope_ttl); });
    if (!id) {
        return std::unexpected(id.error());
    }
    {
        std::lock_guard lock(mutex_);
        restart_delay_ = options_.restart_min;
    }
    return VaultScope(std::move(generation), *id);
}

std::optional<std::uint64_t> VaultService::vault_pid() const {
    std::lock_guard lock(mutex_);
    if (!current_ || current_->is_dead()) {
        return std::nullopt;
    }
    return current_->process.ready().pid;
}

}  // namespace prompt_airlock::vault_client
