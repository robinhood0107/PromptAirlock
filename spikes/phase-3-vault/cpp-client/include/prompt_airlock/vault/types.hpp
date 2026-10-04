// Vault 클라이언트 공용 타입. 원문 값은 SensitiveValue 로만 다루고 복사를 막는다.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

// view 반환 API 에 수명 경고를 붙인다(clang). 다른 컴파일러에서는 비운다.
#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(clang::lifetimebound)
#define PA_LIFETIMEBOUND [[clang::lifetimebound]]
#endif
#endif
#ifndef PA_LIFETIMEBOUND
#define PA_LIFETIMEBOUND
#endif

namespace prompt_airlock::vault {

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
};

std::string_view to_string(ErrorCode c) noexcept;

// 오류에는 코드만 담는다. 원문·token·scope id 를 넣지 않는다.
struct Error {
    ErrorCode code;
    friend bool operator==(const Error&, const Error&) = default;
};

template <class T>
using Result = std::expected<T, Error>;

inline std::unexpected<Error> fail(ErrorCode c) { return std::unexpected(Error{c}); }

// 메모리를 컴파일러 최적화에 지워지지 않게 0 으로 채운다.
void secure_wipe(void* p, std::size_t n) noexcept;
// 용량 전체를 지운다. 표준상 size 밖은 쓸 수 없으므로 먼저 capacity 까지 늘린 뒤 지운다.
inline void secure_wipe(std::string& s) noexcept {
    s.resize(s.capacity());
    secure_wipe(s.data(), s.size());
    s.clear();
}

class ScopeId {
public:
    static constexpr std::size_t size = 16;
    static Result<ScopeId> from_bytes(std::span<const std::uint8_t> b);
    std::span<const std::uint8_t, size> bytes() const noexcept { return bytes_; }
    friend bool operator==(const ScopeId&, const ScopeId&) = default;

private:
    std::array<std::uint8_t, size> bytes_{};
};

class Token {
public:
    explicit Token(std::string s) : value_(std::move(s)) {}
    const std::string& str() const noexcept { return value_; }
    friend bool operator==(const Token&, const Token&) = default;

private:
    std::string value_;
};

class EntityLabel {
public:
    // 1~24자, [A-Z][A-Z0-9_]*. Vault 와 같은 규칙.
    static Result<EntityLabel> parse(std::string_view s);
    const std::string& str() const noexcept { return value_; }

private:
    explicit EntityLabel(std::string s) : value_(std::move(s)) {}
    std::string value_;
};

// 복원된 원문. 이동만 가능하고 소멸 시 지운다.
class SensitiveValue {
public:
    SensitiveValue(std::string label, std::string data) : label_(std::move(label)), data_(std::move(data)) {}
    SensitiveValue(const SensitiveValue&) = delete;
    SensitiveValue& operator=(const SensitiveValue&) = delete;
    SensitiveValue(SensitiveValue&& o) noexcept : label_(std::move(o.label_)), data_(std::move(o.data_)) {
        secure_wipe(o.data_);
    }
    SensitiveValue& operator=(SensitiveValue&& o) noexcept {
        if (this != &o) {
            secure_wipe(data_);
            label_ = std::move(o.label_);
            data_ = std::move(o.data_);
            secure_wipe(o.data_);
        }
        return *this;
    }
    ~SensitiveValue() { secure_wipe(data_); }

    std::string_view view() const noexcept PA_LIFETIMEBOUND { return data_; }
    const std::string& label() const noexcept { return label_; }

private:
    std::string label_;
    std::string data_;
};

// 실행별 32바이트 인증 비밀값. 이동만 가능하고 소멸 시 지운다.
class AuthSecret {
public:
    static constexpr std::size_t size = 32;
    static Result<AuthSecret> from_hex(std::string_view hex);
    AuthSecret(const AuthSecret&) = delete;
    AuthSecret& operator=(const AuthSecret&) = delete;
    AuthSecret(AuthSecret&& o) noexcept : bytes_(o.bytes_) { secure_wipe(o.bytes_.data(), size); }
    AuthSecret& operator=(AuthSecret&& o) noexcept {
        bytes_ = o.bytes_;
        secure_wipe(o.bytes_.data(), size);
        return *this;
    }
    ~AuthSecret() { secure_wipe(bytes_.data(), size); }
    std::span<const std::uint8_t, size> bytes() const noexcept { return bytes_; }

private:
    AuthSecret() = default;
    std::array<std::uint8_t, size> bytes_{};
};

enum class TransportKind : std::uint8_t { Tcp, NamedPipe, UnixSocket };

struct Endpoint {
    TransportKind kind;
    // tcp: "127.0.0.1:port", pipe: "\\.\pipe\...", uds: 소켓 경로
    std::string address;
};

}  // namespace prompt_airlock::vault
