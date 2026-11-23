#include "prompt_airlock/gateway/confirm.hpp"

#include <random>
#include <algorithm>

namespace prompt_airlock::gateway {

bool valid_confirmation_token(std::string_view token) noexcept {
    return token.size() == confirm_token_chars && std::ranges::all_of(token, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

std::optional<std::string> ConfirmLedger::issue(std::string_view body_sha256, std::string_view origin) {
    std::random_device device;  // 운영체제 난수(MSVC rand_s, Linux /dev/urandom)
    std::string token;
    constexpr std::string_view hex = "0123456789abcdef";
    for (std::size_t i = 0; i < confirm_token_chars; ++i) {
        token.push_back(hex[device() % 16]);
    }
    std::lock_guard lock(mutex_);
    const auto now = now_();
    std::erase_if(entries_, [&](const auto& e) { return e.second.expires <= now; });
    if (entries_.size() >= confirm_capacity) {
        return std::nullopt;
    }
    entries_.insert_or_assign(token, Entry{std::string(body_sha256), std::string(origin), now + confirm_ttl});
    return token;
}

bool ConfirmLedger::redeem(std::string_view token, std::string_view body_sha256, std::string_view origin) {
    std::lock_guard lock(mutex_);
    const auto now = now_();
    const auto found = entries_.find(std::string(token));
    if (found == entries_.end() || found->second.origin != origin) {
        return false;
    }
    const bool ok = found->second.expires > now && found->second.body_sha256 == body_sha256;
    entries_.erase(found);
    return ok;
}

bool ConfirmLedger::approve(std::string_view token, std::string_view origin,
                            const std::function<bool(std::string_view)>& check) {
    std::lock_guard lock(mutex_);
    const auto found = entries_.find(std::string(token));
    if (found == entries_.end() || found->second.origin != origin ||
        found->second.expires <= now_() || found->second.state != State::Pending) return false;
    if (!check(found->second.body_sha256)) return false;
    if (found->second.expires <= now_()) return false;
    found->second.state = State::Approved;
    return true;
}

bool ConfirmLedger::redeem_approved(std::string_view body_sha256, std::string_view origin) {
    std::lock_guard lock(mutex_);
    const auto now = now_();
    for (auto entry = entries_.begin(); entry != entries_.end(); ++entry) {
        if (entry->second.state == State::Approved && entry->second.expires > now &&
            entry->second.origin == origin && entry->second.body_sha256 == body_sha256) {
            entries_.erase(entry);
            return true;
        }
    }
    return false;
}

ConfirmationList ConfirmLedger::list_for_origin(std::string_view origin) {
    struct Candidate {
        Clock::time_point expires;
        ConfirmationListItem item;
    };
    std::lock_guard lock(mutex_);
    const auto now = now_();
    std::vector<Candidate> candidates;
    for (const auto& [token, entry] : entries_) {
        if (entry.origin != origin || entry.expires <= now || !valid_confirmation_token(token)) continue;
        const auto seconds = std::chrono::ceil<std::chrono::seconds>(entry.expires - now).count();
        const bool approved = entry.state == State::Approved;
        candidates.push_back({entry.expires, {approved ? std::string{} : token, approved,
                                               static_cast<std::uint32_t>(seconds)}});
    }
    std::ranges::sort(candidates, [](const Candidate& left, const Candidate& right) {
        if (left.expires != right.expires) return left.expires < right.expires;
        return left.item.approval_mark < right.item.approval_mark;
    });

    ConfirmationList result;
    result.truncated = candidates.size() > confirmation_list_limit;
    const auto count = std::min(candidates.size(), confirmation_list_limit);
    result.items.reserve(count);
    for (std::size_t i = 0; i < count; ++i) result.items.push_back(std::move(candidates[i].item));
    return result;
}

}  // namespace prompt_airlock::gateway
