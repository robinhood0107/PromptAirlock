#pragma once

#include <cstdint>

#include "prompt_airlock/core/research.hpp"

namespace prompt_airlock::core {

enum class PrivacyStrategyKind : std::uint8_t { NoProtection, Redaction, TypeMask, UniquePseudonym };

// 가명화 전략(spec §25). 운영 정책은 항상 UniquePseudonym 이다.
// 보호 없음은 연구용 열쇠가 있어야만 만들 수 있다(invariant 12).
class PrivacyStrategy {
public:
    [[nodiscard]] static constexpr PrivacyStrategy unique_pseudonym() noexcept {
        return PrivacyStrategy(PrivacyStrategyKind::UniquePseudonym);
    }
    // 값을 "⟦REDACTED⟧" 로 바꾼다. 복원하지 않는다.
    [[nodiscard]] static constexpr PrivacyStrategy redaction() noexcept {
        return PrivacyStrategy(PrivacyStrategyKind::Redaction);
    }
    // 값을 "⟦PERSON⟧" 처럼 종류만 남긴다. R 이 없어 token 모양이 아니며 복원하지 않는다.
    [[nodiscard]] static constexpr PrivacyStrategy type_mask() noexcept {
        return PrivacyStrategy(PrivacyStrategyKind::TypeMask);
    }
    [[nodiscard]] static constexpr PrivacyStrategy no_protection(ResearchOnly) noexcept {
        return PrivacyStrategy(PrivacyStrategyKind::NoProtection);
    }

    [[nodiscard]] constexpr PrivacyStrategyKind kind() const noexcept { return kind_; }
    constexpr bool operator==(const PrivacyStrategy&) const noexcept = default;

private:
    constexpr explicit PrivacyStrategy(PrivacyStrategyKind kind) noexcept : kind_(kind) {}
    PrivacyStrategyKind kind_;
};

}  // namespace prompt_airlock::core
