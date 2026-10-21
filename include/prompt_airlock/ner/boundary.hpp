// NER 결과 경계 다듬기(Phase 7-3, 결정 #107). 입출력 없는 순수 함수.
// 모델이 낸 구간을 정답 규칙에 맞춘다: 어절 단위로 넓히고, 이름이 아닌 꼬리와 머리를 뗀다.
#pragma once

#include <cstdint>
#include <optional>

#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/types.hpp"
#include "prompt_airlock/detect/view.hpp"

namespace prompt_airlock::ner {

// first..last 는 모델이 낸 보기 구간(양 끝 포함)이다. 순서:
//   1. 앞뒤 부호를 떼고 이어지는 글자까지 넓힌다(이름 조각이 남아 그대로 나가는 일을 막는다).
//   2. 기관이면 앞의 법인 표기((주), 주식회사, 재단법인 등)와 뒤의 부서명(보안팀 등)을 뗀다.
//   3. 뒤의 조사·호칭(core::trim_trailing_particles), 직함(숫자 붙은 직함 포함), 서술격 조사를 더 줄지 않을 때까지 뗀다.
//   4. 기관인데 일반 부서명뿐이면(영업본부, 고객센터) 이름이 아니므로 nullopt.
// 떼는 쪽은 글자가 두 개 넘게 남을 때만 뗀다. 부호뿐이어도 nullopt. 결과는 원문 byte 구간이다.
[[nodiscard]] std::optional<core::ByteSpan> name_span(const detect::DetectionView& view, std::uint32_t first,
                                                      std::uint32_t last, core::EntityType type);

}  // namespace prompt_airlock::ner
