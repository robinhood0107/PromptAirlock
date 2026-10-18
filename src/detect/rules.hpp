// 탐지기 내부 공통 타입. 공개하지 않는다(include/ 에 없음).
#pragma once

#include <compare>
#include <cstdint>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/types.hpp"
#include "prompt_airlock/detect/view.hpp"

namespace prompt_airlock::detect::rules {

// 보기 위치 [first, last] 의 탐지 결과. 원문 위치로는 detectors.cpp 가 바꾼다.
struct Hit {
    std::uint32_t first;
    std::uint32_t last;
    core::EntityType type;
    core::DetectorKind kind;
    auto operator<=>(const Hit&) const noexcept = default;
};

// text 는 view.units 의 글자만 모은 문자열이다(위치가 같다).
void find_identifiers(const DetectionView& view, std::u32string_view text, std::vector<Hit>& out);
void find_network(std::u32string_view text, std::vector<Hit>& out);
void find_secrets(std::u32string_view text, std::vector<Hit>& out);

}  // namespace prompt_airlock::detect::rules
