// 탐지용 보기에서 숫자 후보를 찾는다. 한 번 앞으로 지나가며 O(n) 이다.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "prompt_airlock/detect/view.hpp"

namespace prompt_airlock::detect {

// 계좌번호 최대 길이(IBAN 34자). 숫자가 이보다 많은 묶음은 번호 후보가 아니다.
inline constexpr std::size_t max_digit_run = 34;

// 구분자(하이픈·공백·점·대시류)로 이어진 ASCII 숫자 묶음. 앞뒤가 영문·숫자에 붙어 있으면 후보가 아니다.
struct DigitGroup {
    std::uint32_t first_unit;
    std::uint32_t last_unit;
    std::string digits;
    char32_t separator = 0;  // 다음 묶음과의 첫 구분자(마지막 묶음은 0)
};
struct DigitRun {
    std::vector<DigitGroup> groups;
};

[[nodiscard]] std::vector<DigitRun> digit_runs(const DetectionView& view);

// 문장 구간 [first_unit, end_unit). 종결 부호(. ? ! 。 …) 뒤에 공백·줄바꿈·끝이 오거나 줄바꿈이면 끝난다.
// "3.14", "v1.2" 처럼 부호 뒤에 바로 글자가 오면 경계가 아니다. 긴 문장도 자르지 않는다.
struct SentenceSpan {
    std::uint32_t first_unit;
    std::uint32_t end_unit;
};
[[nodiscard]] std::vector<SentenceSpan> sentences(const DetectionView& view);

[[nodiscard]] constexpr bool is_ascii_digit(char32_t c) noexcept { return c >= U'0' && c <= U'9'; }
[[nodiscard]] constexpr bool is_ascii_alpha(char32_t c) noexcept {
    return (c >= U'A' && c <= U'Z') || (c >= U'a' && c <= U'z');
}
[[nodiscard]] constexpr bool is_ascii_alnum(char32_t c) noexcept { return is_ascii_digit(c) || is_ascii_alpha(c); }
[[nodiscard]] constexpr char32_t ascii_lower(char32_t c) noexcept {
    return c >= U'A' && c <= U'Z' ? c + (U'a' - U'A') : c;
}

}  // namespace prompt_airlock::detect
