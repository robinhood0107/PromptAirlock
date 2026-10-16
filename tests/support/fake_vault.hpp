#pragma once

// 시험 전용 가짜 Vault: token 발급기와 복원기. 운영 코드는 이 헤더를 쓰지 않는다(Phase 6 에서 실제 Vault).
// 규칙은 ADR 0008 과 같다. 같은 범위·같은 (종류, 값) → 같은 token, 중복 R 거절, R 에 원문 4자 없음,
// 복원은 정확히 같은 token 만. R 은 seed 로 정해지는 결정적 난수라 운영에 쓰면 안 된다.
#include <algorithm>
#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <string_view>
#include <utility>

#include "prng.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/sensitive.hpp"
#include "prompt_airlock/core/token.hpp"
#include "prompt_airlock/core/types.hpp"

namespace pa_test {

class FakeVault {
public:
    explicit FakeVault(std::uint64_t seed) noexcept : rng_(seed) {}

    std::expected<prompt_airlock::core::Token, prompt_airlock::core::ProtectionError> issue(
        prompt_airlock::core::EntityType type, std::string_view value) {
        namespace pc = prompt_airlock::core;
        const auto key = std::pair{type, std::string(value)};
        if (const auto found = by_value_.find(key); found != by_value_.end()) {
            return found->second;
        }
        const auto label = pc::token_label(type);
        if (!label) {
            return std::unexpected(pc::ProtectionError::LabelMismatch);
        }
        for (int attempt = 0; attempt < 64; ++attempt) {
            std::string random;
            for (std::size_t i = 0; i < pc::token_random_length; ++i) {
                random.push_back(pc::token_alphabet[rng_.below(pc::token_alphabet.size())]);
            }
            if (leaks(random, value)) {
                continue;
            }
            const auto text =
                std::string(pc::token_open) + std::string(*label) + "_" + random + std::string(pc::token_close);
            if (by_token_.contains(text)) {
                continue;
            }
            auto token = pc::parse_token(text);
            by_value_.emplace(key, *token);
            by_token_.emplace(text, std::string(value));
            return *token;
        }
        return std::unexpected(pc::ProtectionError::IssuerUnavailable);
    }

    std::expected<prompt_airlock::core::SensitiveText, prompt_airlock::core::RestoreError> resolve(
        const prompt_airlock::core::Token& token) const {
        const auto found = by_token_.find(std::string(token.text()));
        if (found == by_token_.end()) {
            return std::unexpected(prompt_airlock::core::RestoreError::TokenNotFound);
        }
        return prompt_airlock::core::SensitiveText::copy_of(found->second);
    }

    [[nodiscard]] std::size_t issued() const noexcept { return by_token_.size(); }

private:
    static bool leaks(std::string_view random, std::string_view value) {
        const auto width = std::min<std::size_t>(value.size(), 4);
        const auto upper = [](char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c; };
        for (std::size_t v = 0; width > 0 && v + width <= value.size(); ++v) {
            for (std::size_t r = 0; r + width <= random.size(); ++r) {
                if (std::equal(random.begin() + r, random.begin() + r + width, value.begin() + v,
                               [&](char a, char b) { return upper(a) == upper(b); })) {
                    return true;
                }
            }
        }
        return false;
    }

    SplitMix64 rng_;
    std::map<std::pair<prompt_airlock::core::EntityType, std::string>, prompt_airlock::core::Token> by_value_;
    std::map<std::string, std::string> by_token_;
};

}  // namespace pa_test
