#pragma once

#include <span>

#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/utf8.hpp"

namespace prompt_airlock::core {

// 이름·조직 탐지 구간 끝에 붙은 조사·호칭을 떼어 낸다(Phase 2 실험 규칙, ADR 0006).
// 받침 호응(은/는, 이/가, 을/를, 과/와, 으로/로 등)이 맞고 최소 음절이 남을 때만 자르며, 최대 두 번 자른다.
// units 는 원문 위치 순서로 정렬된 코드포인트다(원문을 decode_utf8 한 것이거나 Phase 5 탐지용 보기).
// 구간 안에 완전히 들어가는 unit 만 본다. 결과는 항상 비어 있지 않다.
[[nodiscard]] ByteSpan trim_trailing_particles(std::span<const DecodedCodepoint> units, ByteSpan span) noexcept;

}  // namespace prompt_airlock::core
