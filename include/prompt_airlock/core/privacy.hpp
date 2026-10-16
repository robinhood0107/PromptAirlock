#pragma once

#include <concepts>
#include <expected>
#include <string_view>
#include <utility>
#include <vector>

#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/prompt.hpp"
#include "prompt_airlock/core/reason.hpp"
#include "prompt_airlock/core/strategy.hpp"
#include "prompt_airlock/core/token.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// token 발급기. Phase 6 에서는 Vault client 가 구현하고, 시험은 가짜 발급기를 쓴다.
// value 는 호출 동안만 유효하므로 구현은 돌려주기 전에 복사해야 한다.
// 같은 범위에서 같은 (종류, 값) 이면 같은 token, 다른 값이면 다른 token 을 줘야 한다(ADR 0008).
template <class I>
concept TokenIssuer = requires(I& issuer, EntityType type, std::string_view value) {
    { issuer.issue(type, value) } -> std::same_as<std::expected<Token, ProtectionError>>;
};

// 가명으로 바꿀 자리. 정책 검사에서 Tokenize 로 합쳐진 탐지 결과다.
struct ProtectionTarget {
    SegmentIndex segment;
    ByteSpan span;
    EntityType label_type;
    bool operator==(const ProtectionTarget&) const noexcept = default;
};

// 바꿀 자리를 segment·위치 순으로 돌려준다.
[[nodiscard]] std::vector<ProtectionTarget> protection_targets(const PolicyCheckedPrompt& prompt);

// 전략대로 텍스트를 다시 써 보호 단계를 만든다. UniquePseudonym 이면 tokens[i] 가 targets[i] 의 token 이고,
// 다른 전략이면 tokens 는 비어 있어야 한다. 발급기를 믿지 않고 다시 확인한다:
// 개수, 라벨, 같은 값 같은 token·다른 값 다른 token, R 에 원문 연속 4자 없음. 어기면 ProtectionUnavailable.
// prompt 는 값으로 받으므로 원문은 이 함수가 끝날 때 지워진다.
[[nodiscard]] std::expected<ProtectedPrompt, Rejection> apply_protection(PolicyCheckedPrompt prompt,
                                                                         std::vector<Token> tokens);

// 발급기로 token 을 받아 apply_protection 을 부른다.
template <TokenIssuer I>
[[nodiscard]] std::expected<ProtectedPrompt, Rejection> protect(PolicyCheckedPrompt prompt, I& issuer) {
    std::vector<Token> tokens;
    if (prompt.strategy().kind() == PrivacyStrategyKind::UniquePseudonym) {
        const auto targets = protection_targets(prompt);
        const auto segments = prompt.document().segments();
        tokens.reserve(targets.size());
        for (const auto& target : targets) {
            const auto value = segments[target.segment.value()].text().substr(target.span.begin().value(),
                                                                               target.span.size());
            auto token = issuer.issue(target.label_type, value);
            if (!token) {
                return std::unexpected(Rejection::from_error(token.error()));
            }
            tokens.push_back(std::move(*token));
        }
    }
    return apply_protection(std::move(prompt), std::move(tokens));
}

}  // namespace prompt_airlock::core
