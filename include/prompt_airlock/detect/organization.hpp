// 기관명 끝말(꼬리) 판정(Phase 7-3). 결정론 기관 규칙과 NER 종류 바로잡기가 함께 쓴다.
// 목록은 이 저장소의 시험 셋이 아니라 일반적인 한국어 기관명 표기에서 가져왔다.
#pragma once

#include <cstddef>
#include <string_view>

namespace prompt_airlock::detect {

enum class OrgTails : unsigned char {
    // 앞말이 붙은 어절만 보고 기관이라고 정할 때 쓴다. 일반어와 붙어 흔히 쓰이는 꼬리(보험, 카드, 산업 등)는 뺐다.
    Strict,
    // 모델이 이미 이름으로 찾은 구간의 종류를 바로잡을 때 쓴다(도담디자인을 사람으로 본 경우).
    Broad,
};

// word 가 목록의 꼬리로 끝나면 그 꼬리의 글자 수, 아니면 0. 가장 긴 꼬리를 고른다.
[[nodiscard]] std::size_t org_tail_length(std::u32string_view word, OrgTails tails) noexcept;

}  // namespace prompt_airlock::detect
