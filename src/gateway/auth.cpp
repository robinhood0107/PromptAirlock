#include "prompt_airlock/gateway/auth.hpp"

#include <algorithm>
#include <span>
#include <utility>

#include "prompt_airlock/core/sha256.hpp"

namespace prompt_airlock::gateway {
namespace {

// 발급 token 은 base64url 43자이지만, 길이로 출처를 드러내지 않도록 보이는 ASCII 1~256자를 모두 해시까지 보낸다.
constexpr std::size_t max_token_length = 256;

bool ascii_iequal(std::string_view a, std::string_view b) {
    return a.size() == b.size() && std::ranges::equal(a, b, [](char x, char y) {
               const auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; };
               return lower(x) == lower(y);
           });
}

std::expected<std::string_view, AuthFailure> bearer_token(std::string_view header) {
    if (header.empty()) {
        return std::unexpected(AuthFailure::Missing);
    }
    constexpr std::string_view scheme = "bearer ";
    if (header.size() <= scheme.size() || !ascii_iequal(header.substr(0, scheme.size()), scheme)) {
        return std::unexpected(AuthFailure::Malformed);
    }
    const std::string_view token = header.substr(scheme.size());
    if (token.size() > max_token_length ||
        !std::ranges::all_of(token, [](char c) { return c > 0x20 && c < 0x7f; })) {
        return std::unexpected(AuthFailure::Malformed);
    }
    return token;
}

// 길이가 같은 두 값을 끝까지 비교한다(앞에서 다르다고 일찍 끝내지 않는다).
bool constant_time_equal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned>(static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]));
    }
    return diff == 0;
}

}  // namespace

Authenticator::Authenticator(std::vector<Origin> origins) : origins_(std::move(origins)) {}

std::expected<const Origin*, AuthFailure> Authenticator::authenticate(std::string_view authorization,
                                                                      std::string_view client, Clock::time_point now) {
    const std::string key(client);
    std::scoped_lock lock(mutex_);
    if (const auto it = failures_.find(key); it != failures_.end() && it->second.locked_until > now) {
        return std::unexpected(AuthFailure::Locked);
    }
    const auto token = bearer_token(authorization);
    if (!token) {
        record_failure(key, now);
        return std::unexpected(token.error());
    }
    const std::string digest = core::sha256_hex(std::as_bytes(std::span(token->data(), token->size())));
    // 등록 출처를 모두 비교한다. 어느 출처와 맞았는지가 시간으로 드러나지 않게 중간에 멈추지 않는다.
    const Origin* match = nullptr;
    for (const Origin& origin : origins_) {
        if (constant_time_equal(digest, origin.token_sha256)) {
            match = &origin;
        }
    }
    if (match == nullptr) {
        record_failure(key, now);
        return std::unexpected(AuthFailure::Unknown);
    }
    failures_.erase(key);
    return match;
}

void Authenticator::record_failure(const std::string& client, Clock::time_point now) {
    if (!failures_.contains(client) && failures_.size() >= max_tracked_clients) {
        std::erase_if(failures_, [now](const auto& entry) { return entry.second.locked_until <= now; });
        // shortcut: 잠긴 주소만으로 표가 가득 차면 새 주소의 실패는 세지 않는다(401 은 그대로). 여러 주소를 쓰는 공격이 보이면 전역 속도 제한을 더한다.
        if (failures_.size() >= max_tracked_clients) {
            return;
        }
    }
    Failures& f = failures_[client];
    if (++f.count >= max_failures) {
        f.count = 0;
        f.locked_until = now + lock_duration;
    }
}

std::string_view auth_failure_name(AuthFailure failure) noexcept {
    switch (failure) {
        case AuthFailure::Missing: return "missing";
        case AuthFailure::Malformed: return "malformed";
        case AuthFailure::Unknown: return "unknown";
        case AuthFailure::Locked: return "locked";
    }
    return "unknown";
}

}  // namespace prompt_airlock::gateway
