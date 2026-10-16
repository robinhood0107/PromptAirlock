#pragma once

#include <expected>
#include <vector>

#include "prompt_airlock/core/encoded.hpp"
#include "prompt_airlock/core/entity.hpp"
#include "prompt_airlock/core/prompt.hpp"
#include "prompt_airlock/core/reason.hpp"

namespace prompt_airlock::core {

// 보호 후 텍스트를 다시 탐지한 결과(위치는 보호 후 텍스트 기준).
struct ResidualReport {
    std::vector<EntitySpan> entities;
    std::vector<EncodedFinding> encoded;
};

// 잔여 검사(spec §28). 순서: 결과 수 한도, 위치 재대조(맞지 않으면 DetectorUnavailable),
// 바꿔 넣은 자리 안에 완전히 들어간 결과는 무시(생성한 token·표지라 원문이 없다),
// 남은 가명화·차단 대상이 있으면 ResidualFound, 인코딩 판정(judge_encoded)을 통과해야 검증 완료.
// 인코딩 판정의 필수 관문은 여기다. Phase 5 가 더 일찍 judge_encoded 를 불러도 된다.
[[nodiscard]] std::expected<VerifiedPrompt, Rejection> verify_residual(ProtectedPrompt prompt,
                                                                       const ResidualReport& report);

}  // namespace prompt_airlock::core
