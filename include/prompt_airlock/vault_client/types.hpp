// Vault 클라이언트 공용 타입. 원문 값은 core::SensitiveText 로만 다룬다(ADR 0019).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace prompt_airlock::vault_client {

enum class ErrorCode : std::uint8_t {
    // Vault 가 돌려준 코드(proto ErrorCode 와 1:1)
    UnsupportedVersion,
    MalformedRequest,
    FrameTooLarge,
    AuthRequired,
    AuthFailed,
    Overloaded,
    ScopeNotFound,
    ScopeExpired,
    TokenNotFound,
    MalformedToken,
    ScopeLimit,
    MappingLimit,
    ValueTooLarge,
    InvalidArgument,
    Internal,
    ShuttingDown,
    // 클라이언트 측에서 판정한 실패
    Timeout,
    Disconnected,
    Io,
    ProtocolViolation,
    ConnectFailed,
    ServerIdentityMismatch,
    ClientBroken,
    SpawnFailed,
    ReadyLineInvalid,
    PoolExhausted,     // 연결 풀에서 제한 시간 안에 연결을 빌리지 못함
    RestartPending,    // Vault 가 죽은 뒤 재시작 간격이 아직 지나지 않음
};

[[nodiscard]] std::string_view to_string(ErrorCode c) noexcept;

// 오류에는 코드만 담는다. 원문·token·scope id·비밀값을 넣지 않는다.
struct Error {
    ErrorCode code;
    friend bool operator==(const Error&, const Error&) = default;
};

template <class T>
using Result = std::expected<T, Error>;

[[nodiscard]] inline std::unexpected<Error> fail(ErrorCode c) { return std::unexpected(Error{c}); }

// 문자열의 용량 전체를 지운다. 표준상 size 밖은 쓸 수 없으므로 capacity 까지 늘린 뒤 지운다(SSO 영역 포함).
void wipe(std::string& s) noexcept;

class ScopeId {
public:
    static constexpr std::size_t size = 16;
    [[nodiscard]] static Result<ScopeId> from_bytes(std::span<const std::uint8_t> b);
    [[nodiscard]] std::span<const std::uint8_t, size> bytes() const noexcept { return bytes_; }
    friend bool operator==(const ScopeId&, const ScopeId&) = default;

private:
    std::array<std::uint8_t, size> bytes_{};
};

// 실행별 32바이트 인증 비밀값. 이동만 가능하고 소멸 시 지운다.
class AuthSecret {
public:
    static constexpr std::size_t size = 32;
    [[nodiscard]] static Result<AuthSecret> from_hex(std::string_view hex);
    AuthSecret(const AuthSecret&) = delete;
    AuthSecret& operator=(const AuthSecret&) = delete;
    AuthSecret(AuthSecret&& o) noexcept;
    AuthSecret& operator=(AuthSecret&& o) noexcept;
    ~AuthSecret();
    [[nodiscard]] std::span<const std::uint8_t, size> bytes() const noexcept { return bytes_; }

private:
    AuthSecret() = default;
    std::array<std::uint8_t, size> bytes_{};
};

// 로컬 transport 만 있다. TCP 는 없다(ADR 0003).
enum class TransportKind : std::uint8_t { NamedPipe, UnixSocket };

struct Endpoint {
    TransportKind kind;
    std::string address;  // pipe: "\\.\pipe\...", uds: 소켓 경로
};

}  // namespace prompt_airlock::vault_client
