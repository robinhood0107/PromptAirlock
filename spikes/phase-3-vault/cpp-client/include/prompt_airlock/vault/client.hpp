// Vault 클라이언트. 연결 하나는 한 스레드에서만 쓴다(요청-응답 순차).
// transport 오류·timeout·프로토콜 위반이 한 번이라도 나면 클라이언트는 broken 상태가 되고
// 이후 모든 호출은 ClientBroken 으로 실패한다(fail closed, 추측·재시도 없음).
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>

#include "prompt_airlock/vault/stream.hpp"
#include "prompt_airlock/vault/types.hpp"

namespace prompt_airlock::vault {

struct ClientOptions {
    StreamOptions stream{};
    std::chrono::milliseconds io_timeout{2000};
    std::size_t max_frame_bytes = 64 * 1024;
};

class VaultClient {
public:
    static Result<VaultClient> connect(const Endpoint& ep, const AuthSecret& secret, const ClientOptions& opts = {});

    VaultClient(VaultClient&&) noexcept;
    VaultClient& operator=(VaultClient&&) noexcept;
    VaultClient(const VaultClient&) = delete;
    VaultClient& operator=(const VaultClient&) = delete;
    ~VaultClient();

    Result<ScopeId> create_scope(std::chrono::milliseconds ttl);
    Result<Token> create_token(const ScopeId& scope, const EntityLabel& label, std::string_view value);
    Result<SensitiveValue> resolve_exact(const ScopeId& scope, const Token& token);
    Result<void> drop_scope(const ScopeId& scope);

    bool broken() const noexcept;

private:
    struct Impl;
    explicit VaultClient(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

// scope 수명을 묶는 RAII. 소멸 시 DropScope 를 보낸다(실패해도 TTL 이 최종 정리).
class ScopeGuard {
public:
    ScopeGuard(VaultClient& c, ScopeId id) : client_(&c), id_(id) {}
    ScopeGuard(ScopeGuard&& o) noexcept : client_(std::exchange(o.client_, nullptr)), id_(o.id_) {}
    ScopeGuard& operator=(ScopeGuard&&) = delete;
    ScopeGuard(const ScopeGuard&) = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;
    ~ScopeGuard() {
        if (client_ != nullptr) {
            (void)client_->drop_scope(id_);
        }
    }
    const ScopeId& id() const noexcept { return id_; }

private:
    VaultClient* client_;
    ScopeId id_;
};

}  // namespace prompt_airlock::vault
