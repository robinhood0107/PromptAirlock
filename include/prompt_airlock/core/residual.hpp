#pragma once

#include <expected>
#include <string_view>
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

// 잔여 검사에 넘길 사본. 가명 token 의 무작위 10자만 고정 글자(residual_scan_filler)로 바꾼다(길이·위치 그대로).
// 무작위 글자가 NER 문맥을 흔들어 같은 문서의 판정이 실행마다 바뀌는 것을 막는다. 보내는 글은 바꾸지 않는다.
inline constexpr std::string_view residual_scan_filler = "XXXXXXXXXX";  // 실제 자료 132개 후보 5개 중 잔여 차단 최소(2026-11-09)
// filler 는 token_random_length 바이트 ASCII 여야 한다(측정 도구가 후보를 비교할 때만 바꾼다).
[[nodiscard]] PromptDocument residual_scan_document(const ProtectedPrompt& prompt,
                                                    std::string_view filler = residual_scan_filler);

// 잔여 검사(spec §28). 순서: 결과 수 한도, 위치 재대조(맞지 않으면 DetectorUnavailable),
// 바꿔 넣은 자리 안에 완전히 들어간 결과는 무시(생성한 token·표지라 원문이 없다),
// 남은 가명화·차단 대상이 있으면 ResidualFound, 인코딩 판정(judge_encoded)을 통과해야 검증 완료.
// 인코딩 판정의 필수 관문은 여기다. Phase 5 가 더 일찍 judge_encoded 를 불러도 된다.
[[nodiscard]] std::expected<VerifiedPrompt, Rejection> verify_residual(ProtectedPrompt prompt,
                                                                       const ResidualReport& report);

}  // namespace prompt_airlock::core
