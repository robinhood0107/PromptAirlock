// 요청 본문(JSON) 읽기(ADR 0017, 0020). 허용 필드만 받아 검사 대상 묶음과 요청 파라미터 날 값으로 바꾼다.
// 읽는 도중 허용 밖 키, 중복 키, 깊이 16 초과를 만나면 바로 멈춘다. 라이브러리 예외는 여기서 사유 코드로 바꾼다.
#pragma once

#include <cstddef>
#include <expected>
#include <string_view>

#include "prompt_airlock/core/document.hpp"
#include "prompt_airlock/core/reason.hpp"
#include "prompt_airlock/core/request_params.hpp"

namespace prompt_airlock::gateway {

inline constexpr std::size_t max_json_depth = 16;

struct ParsedRequest {
    core::PromptDocument document;
    core::RequestParamsInput params;
};

// 사유 코드: 문법·UTF-8·깊이 오류는 InvalidText, 허용 밖 키·중복 키·모양이 다른 값은 FieldNotAllowed,
// text 가 아닌 content part 는 ContentPartNotAllowed, 파라미터 형식 오류는 ParameterOutOfRange.
// 묶음 검사(빈 메시지, 크기 상한 등)는 core 의 사유 코드를 그대로 쓴다.
[[nodiscard]] std::expected<ParsedRequest, core::Rejection> parse_request(std::string_view body);

}  // namespace prompt_airlock::gateway
