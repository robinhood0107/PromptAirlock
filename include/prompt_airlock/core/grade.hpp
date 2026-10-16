#pragma once

#include <expected>
#include <span>
#include <string_view>

#include "prompt_airlock/core/detail/state_key.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/reason.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// 요청 등급이 O(공개)로 확정됐다는 증표. resolve_grade 만 만든다(ADR 0013).
class OpenGrade {
public:
    constexpr OpenGrade(detail::StateKey<OpenGrade>, GradeOrigin origin) noexcept : origin_(origin) {}
    [[nodiscard]] constexpr GradeOrigin origin() const noexcept { return origin_; }

private:
    GradeOrigin origin_;
};

// 등급 표시 값 하나를 읽는다. "C", "S", "O" 와 정확히 같아야 한다(공백·소문자 거절).
[[nodiscard]] std::expected<DataGrade, InputError> parse_grade_mark(std::string_view mark) noexcept;

// 출처 등급 정책과 요청의 등급 표시(헤더 값 전부)로 등급을 확정한다.
// OOnly 는 표시가 없으면 O, Declare 는 표시가 있어야 한다. 표시가 여러 개거나 형식이 다르면 미확정.
// C·S·미확정은 거절이며, 이때 provider 는 호출되지 않는다(invariant 21).
[[nodiscard]] std::expected<OpenGrade, Rejection> resolve_grade(GradePolicy policy,
                                                                std::span<const std::string_view> marks) noexcept;

}  // namespace prompt_airlock::core
