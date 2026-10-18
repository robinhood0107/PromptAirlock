// 민감정보 범주와 집계. 범주는 개인정보 보호법 제23조①과 시행령 제18조를 따른다.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace prompt_airlock::detect {

enum class SensitiveCategory : std::uint8_t {
    Health,
    Belief,
    LaborUnion,
    PoliticalParty,
    PoliticalView,
    SexLife,
    Genetic,
    Criminal,
    Biometric,
    Ethnicity,
};
inline constexpr std::size_t sensitive_category_count = 10;

// 범주어가 있었으나 특정 개인 표지가 없어 통과한 문장 수(감사용, 값 없음, ADR 0016). Phase 8 감사 기록이 읽는다.
struct SensitiveTally {
    std::array<std::uint16_t, sensitive_category_count> passed{};
    bool operator==(const SensitiveTally&) const noexcept = default;
};

}  // namespace prompt_airlock::detect
