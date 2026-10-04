#include "prompt_airlock/vault/types.hpp"

#include <algorithm>
#include <atomic>

namespace prompt_airlock::vault {

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
    }
    return "Unknown";
}

void secure_wipe(void* p, std::size_t n) noexcept {
    auto* v = static_cast<volatile unsigned char*>(p);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = 0;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

Result<ScopeId> ScopeId::from_bytes(std::span<const std::uint8_t> b) {
    if (b.size() != size) {
        return fail(ErrorCode::ProtocolViolation);
    }
    ScopeId id;
    std::copy(b.begin(), b.end(), id.bytes_.begin());
    return id;
}

Result<EntityLabel> EntityLabel::parse(std::string_view s) {
    auto upper = [](char c) { return c >= 'A' && c <= 'Z'; };
    auto digit = [](char c) { return c >= '0' && c <= '9'; };
    if (s.empty() || s.size() > 24 || !upper(s.front())) {
        return fail(ErrorCode::InvalidArgument);
    }
    for (char c : s) {
        if (!upper(c) && !digit(c) && c != '_') {
            return fail(ErrorCode::InvalidArgument);
        }
    }
    return EntityLabel(std::string(s));
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

}  // namespace prompt_airlock::vault
