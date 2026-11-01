#include "prompt_airlock/gateway/confirm.hpp"

#include <random>

namespace prompt_airlock::gateway {

std::optional<std::string> ConfirmLedger::issue(std::string_view body_sha256, Clock::time_point now) {
    std::random_device device;  // 운영체제 난수(MSVC rand_s, Linux /dev/urandom)
    std::string token;
    constexpr std::string_view hex = "0123456789abcdef";
    for (std::size_t i = 0; i < confirm_token_chars; ++i) {
        token.push_back(hex[device() % 16]);
    }
    std::lock_guard lock(mutex_);
    std::erase_if(entries_, [&](const auto& e) { return e.second.expires <= now; });
    if (entries_.size() >= confirm_capacity) {
        return std::nullopt;
    }
    entries_.insert_or_assign(token, Entry{std::string(body_sha256), now + confirm_ttl});
    return token;
}

bool ConfirmLedger::redeem(std::string_view token, std::string_view body_sha256, Clock::time_point now) {
    std::lock_guard lock(mutex_);
    const auto found = entries_.find(std::string(token));
    if (found == entries_.end()) {
        return false;
    }
    const bool ok = found->second.expires > now && found->second.body_sha256 == body_sha256;
    entries_.erase(found);
    return ok;
}

}  // namespace prompt_airlock::gateway
