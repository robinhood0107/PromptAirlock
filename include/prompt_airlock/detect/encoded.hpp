// 인코딩 덩어리 찾기와 풀기(ADR 0017, gap-review G4). 판정(거절 여부)은 core judge_encoded 가 한다.
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::detect {

// 원문 안의 인코딩 덩어리 후보. 인코딩은 ASCII 라 원문 byte 위치가 그대로 덩어리 위치다.
struct EncodedCandidate {
    core::ByteSpan source;
    core::EncodingKind kind;
};

// 후보 기준:
// - percent(%XX 3개 이상), HTML 숫자 참조(&#NNN; &#xHH; 2개 이상), \uXXXX(2개 이상): 공백 없는 덩어리 전체
// - hex(16자 이상, 짝수, 0-9a-f), base64url('-' '_' 포함), base64: 영숫자 + / _ - 16자 이상(끝 '=' 2개까지)
// 한 덩어리에는 종류 하나만 준다(percent > HTML > \u > hex > base64url > base64).
[[nodiscard]] std::vector<EncodedCandidate> encoded_candidates(std::string_view text);

// 종류에 맞게 푼다. 형식이 깨졌으면 nullopt.
[[nodiscard]] std::optional<std::string> decode(std::string_view blob, core::EncodingKind kind);

// 엄격 UTF-8 이고 \t \n \r 밖의 제어 문자가 없으면 텍스트다.
[[nodiscard]] bool is_text(std::string_view bytes) noexcept;

// 한 문서에서 볼 덩어리 수 한도. 넘으면 DetectError::Overloaded(fail closed).
inline constexpr std::size_t max_encoded_candidates = core::max_entities;

}  // namespace prompt_airlock::detect
