// Vault 서비스: 프로세스 감독, 연결 풀, 요청 단위 범위(ADR 0019).
// - Vault 는 처음 범위를 열 때 띄운다. 프로세스와 그 연결들을 "세대(generation)"로 묶는다.
// - 연결은 연산 하나 동안만 빌린다. 풀 크기만큼 연결이 모두 쓰이고 있으면 lease_timeout 까지 기다린 뒤 PoolExhausted.
// - 연결이 broken 이 되고 Vault 프로세스가 끝났으면 그 세대를 죽은 것으로 표시한다. 그 세대의 범위로 하는 연산은
//   모두 실패한다(fail closed). 다음 open_scope 가 새 비밀값으로 Vault 를 다시 띄운다.
// - 재시작 간격: 띄울 때마다 다음 재시작은 restart_delay 뒤에야 가능하고, 그 세대에서 범위 하나라도 열리기 전에
//   다시 죽으면 간격이 두 배(restart_max 까지)가 된다. 범위가 열리면 restart_min 으로 돌아간다.
// 여러 스레드가 VaultService 하나를 함께 쓸 수 있다. VaultScope 하나는 요청 하나(한 스레드)가 쓴다.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/sensitive.hpp"
#include "prompt_airlock/core/token.hpp"
#include "prompt_airlock/core/types.hpp"
#include "prompt_airlock/vault_client/connection.hpp"
#include "prompt_airlock/vault_client/types.hpp"

namespace prompt_airlock::vault_client {

struct ServiceOptions {
    std::filesystem::path exe;              // prompt-airlock-vault 실행 파일
    std::vector<std::string> args;          // 한도 등 추가 인자
    std::chrono::milliseconds ready_timeout{10000};
    ConnectionOptions connection{};
    std::size_t pool_size = 8;
    std::chrono::milliseconds lease_timeout{2000};
    std::chrono::milliseconds scope_ttl{300000};  // 범위가 남는 상한. 보통은 요청 끝에 바로 지운다.
    std::chrono::milliseconds restart_min{1000};
    std::chrono::milliseconds restart_max{30000};
};

// ADR 0019 오류 대응표. core 발급·복원 인터페이스는 core 오류만 돌려주므로 여기서 바꾼다.
[[nodiscard]] core::ProtectionError to_protection_error(ErrorCode c) noexcept;
[[nodiscard]] core::RestoreError to_restore_error(ErrorCode c) noexcept;

class VaultService;

// 요청 하나의 Vault 범위. core TokenIssuer·TokenResolver 를 만족한다. 소멸 시 범위를 지운다.
class VaultScope {
public:
    VaultScope(VaultScope&&) noexcept;
    VaultScope& operator=(VaultScope&&) = delete;
    VaultScope(const VaultScope&) = delete;
    VaultScope& operator=(const VaultScope&) = delete;
    ~VaultScope();

    // value 는 호출 동안만 유효하다(core privacy.hpp 계약). Vault 로 보낸 요청 프레임은 지운다.
    [[nodiscard]] std::expected<core::Token, core::ProtectionError> issue(core::EntityType type, std::string_view value);
    [[nodiscard]] std::expected<core::SensitiveText, core::RestoreError> resolve(const core::Token& token);

    // 마지막 실패의 원래 원인(감사 기록용, 사용자에게 보내지 않음).
    [[nodiscard]] std::optional<ErrorCode> last_error() const noexcept { return last_error_; }

private:
    friend class VaultService;
    struct Generation;
    VaultScope(std::shared_ptr<Generation> generation, ScopeId id) noexcept;
    std::shared_ptr<Generation> generation_;
    ScopeId id_;
    std::optional<ErrorCode> last_error_;
};

class VaultService {
public:
    explicit VaultService(ServiceOptions options);
    VaultService(const VaultService&) = delete;
    VaultService& operator=(const VaultService&) = delete;
    ~VaultService();

    // 요청 시작 때 부른다. Vault 가 없거나 죽었으면 (재시작 간격이 지났을 때) 다시 띄운다.
    [[nodiscard]] Result<VaultScope> open_scope();

    // 현재 세대의 Vault pid(시험·운영 확인용). 없거나 죽었으면 nullopt.
    [[nodiscard]] std::optional<std::uint64_t> vault_pid() const;

private:
    ServiceOptions options_;
    mutable std::mutex mutex_;
    std::shared_ptr<VaultScope::Generation> current_;
    std::chrono::steady_clock::time_point next_spawn_{};
    std::chrono::milliseconds restart_delay_;
};

}  // namespace prompt_airlock::vault_client
