#include "prompt_airlock/vault_client/types.hpp"

#include <algorithm>

#include "prompt_airlock/core/sensitive.hpp"

namespace prompt_airlock::vault_client {
namespace {

void wipe_bytes(std::array<std::uint8_t, AuthSecret::size>& b) noexcept {
    core::secure_wipe({reinterpret_cast<char*>(b.data()), b.size()});
}

}  // namespace

std::string_view to_string(ErrorCode c) noexcept {
    switch (c) {
        case ErrorCode::UnsupportedVersion: return "UnsupportedVersion";
        case ErrorCode::MalformedRequest: return "MalformedRequest";
        case ErrorCode::FrameTooLarge: return "FrameTooLarge";
        case ErrorCode::AuthRequired: return "AuthRequired";
        case ErrorCode::AuthFailed: return "AuthFailed";
        case ErrorCode::Overloaded: return "Overloaded";
        case ErrorCode::ScopeNotFound: return "ScopeNotFound";
        case ErrorCode::ScopeExpired: return "ScopeExpired";
        case ErrorCode::TokenNotFound: return "TokenNotFound";
        case ErrorCode::MalformedToken: return "MalformedToken";
        case ErrorCode::ScopeLimit: return "ScopeLimit";
        case ErrorCode::MappingLimit: return "MappingLimit";
        case ErrorCode::ValueTooLarge: return "ValueTooLarge";
        case ErrorCode::InvalidArgument: return "InvalidArgument";
        case ErrorCode::Internal: return "Internal";
        case ErrorCode::ShuttingDown: return "ShuttingDown";
        case ErrorCode::Timeout: return "Timeout";
        case ErrorCode::Disconnected: return "Disconnected";
        case ErrorCode::Io: return "Io";
        case ErrorCode::ProtocolViolation: return "ProtocolViolation";
        case ErrorCode::ConnectFailed: return "ConnectFailed";
        case ErrorCode::ServerIdentityMismatch: return "ServerIdentityMismatch";
        case ErrorCode::ClientBroken: return "ClientBroken";
        case ErrorCode::SpawnFailed: return "SpawnFailed";
        case ErrorCode::ReadyLineInvalid: return "ReadyLineInvalid";
        case ErrorCode::PoolExhausted: return "PoolExhausted";
        case ErrorCode::RestartPending: return "RestartPending";
    }
    return "Unknown";
}

void wipe(std::string& s) noexcept {
    s.resize(s.capacity());
    core::secure_wipe(s);
    s.clear();
}

Result<ScopeId> ScopeId::from_bytes(std::span<const std::uint8_t> b) {
    if (b.size() != size) {
        return fail(ErrorCode::ProtocolViolation);
    }
    ScopeId id;
    std::copy(b.begin(), b.end(), id.bytes_.begin());
    return id;
}

Result<AuthSecret> AuthSecret::from_hex(std::string_view hex) {
    if (hex.size() != size * 2) {
        return fail(ErrorCode::ReadyLineInvalid);
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    AuthSecret s;
    for (std::size_t i = 0; i < size; ++i) {
        const int hi = nibble(hex[2 * i]);
        const int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return fail(ErrorCode::ReadyLineInvalid);
        }
        s.bytes_[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return s;
}

AuthSecret::AuthSecret(AuthSecret&& o) noexcept : bytes_(o.bytes_) { wipe_bytes(o.bytes_); }

AuthSecret& AuthSecret::operator=(AuthSecret&& o) noexcept {
    // 자기 이동이면 아래 wipe 가 자기 값을 지우므로 건너뛴다.
    if (this != &o) {
        bytes_ = o.bytes_;
        wipe_bytes(o.bytes_);
    }
    return *this;
}

AuthSecret::~AuthSecret() { wipe_bytes(bytes_); }

}  // namespace prompt_airlock::vault_client
