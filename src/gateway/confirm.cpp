#include "prompt_airlock/gateway/confirm.hpp"

#include <random>

namespace prompt_airlock::gateway {

std::optional<std::string> ConfirmLedger::issue(std::string_view body_sha256, std::string_view origin, Clock::time_point now) {
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
    entries_.insert_or_assign(token, Entry{std::string(body_sha256), std::string(origin), now + confirm_ttl});
    return token;
}

bool ConfirmLedger::redeem(std::string_view token, std::string_view body_sha256, std::string_view origin,
                           Clock::time_point now) {
    std::lock_guard lock(mutex_);
    const auto found = entries_.find(std::string(token));
    if (found == entries_.end() || found->second.origin != origin) {
        return false;
    }
    const bool ok = found->second.expires > now && found->second.body_sha256 == body_sha256;
    entries_.erase(found);
    return ok;
}

bool ConfirmLedger::approve(std::string_view token, std::string_view origin, Clock::time_point now,
                            const std::function<bool(std::string_view)>& check) {
    std::lock_guard lock(mutex_);
    const auto found = entries_.find(std::string(token));
    if (found == entries_.end() || found->second.origin != origin ||
        found->second.expires <= now || found->second.state != State::Pending) return false;
    if (!check(found->second.body_sha256)) return false;
    found->second.state = State::Approved;
    return true;
}

bool ConfirmLedger::redeem_approved(std::string_view body_sha256, std::string_view origin, Clock::time_point now) {
    std::lock_guard lock(mutex_);
    for (auto entry = entries_.begin(); entry != entries_.end(); ++entry) {
        if (entry->second.state == State::Approved && entry->second.expires > now &&
            entry->second.origin == origin && entry->second.body_sha256 == body_sha256) {
            entries_.erase(entry);
            return true;
        }
    }
    return false;
}

}  // namespace prompt_airlock::gateway
