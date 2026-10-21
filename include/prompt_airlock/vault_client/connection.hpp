// Vault 연결 하나. 한 번에 한 스레드만 쓴다(요청-응답 순차).
// transport 오류·timeout·프로토콜 위반이 한 번이라도 나면 연결은 broken 이 되고 이후 모든 호출은 ClientBroken 으로
// 실패한다(fail closed, 추측·재시도 없음). 연결 풀(service.hpp)이 broken 연결을 버린다.
#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

#include "prompt_airlock/core/sensitive.hpp"
#include "prompt_airlock/vault_client/stream.hpp"
#include "prompt_airlock/vault_client/types.hpp"

namespace prompt_airlock::vault_client {

struct ConnectionOptions {
    StreamOptions stream{};
    std::chrono::milliseconds io_timeout{2000};
    std::size_t max_frame_bytes = 64 * 1024;
};

class VaultConnection {
public:
    [[nodiscard]] static Result<VaultConnection> connect(const Endpoint& ep, const AuthSecret& secret,
                                                         const ConnectionOptions& opts = {});
    // 이미 연(서버 신원을 확인한) 바이트 연결 위에서 인증한다. connect 가 쓰고, fuzz 시험이 가짜 연결로 쓴다.
    [[nodiscard]] static Result<VaultConnection> handshake(std::unique_ptr<ByteStream> stream, const AuthSecret& secret,
                                                           const ConnectionOptions& opts = {});

    VaultConnection(VaultConnection&&) noexcept;
    VaultConnection& operator=(VaultConnection&&) noexcept;
    VaultConnection(const VaultConnection&) = delete;
    VaultConnection& operator=(const VaultConnection&) = delete;
    ~VaultConnection();

    [[nodiscard]] Result<ScopeId> create_scope(std::chrono::milliseconds ttl);
    // label 은 core::token_label 의 값, value 는 원문(요청 프레임은 보낸 뒤 지운다). 돌려주는 것은 token 문자열.
    [[nodiscard]] Result<std::string> create_token(const ScopeId& scope, std::string_view label, std::string_view value);
    // 응답 protobuf 의 값 문자열은 SensitiveText 로 옮긴 뒤 지운다(ADR 0019).
    [[nodiscard]] Result<core::SensitiveText> resolve_exact(const ScopeId& scope, std::string_view token);
    [[nodiscard]] Result<void> drop_scope(const ScopeId& scope);

    [[nodiscard]] bool broken() const noexcept;

private:
    struct Impl;
    explicit VaultConnection(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

}  // namespace prompt_airlock::vault_client
