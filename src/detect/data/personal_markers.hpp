// 특정 개인 표지(ADR 0016 SensitivePersonalInfo). 같은 문장이나 바로 앞 문장에 범주어와 함께 있으면 차단한다.
// 원천: ADR 0016(이름, 개인 식별 정보, 호칭, 자기 진술)을 따라 직접 작성한 사전. 확인일 2026-10-18.
// 식별 정보 표지는 다른 탐지기 결과(전화, 이메일, 주민·외국인등록, 여권, 면허, 카드, 계좌)를 그대로 쓴다.
// 이름(NER)은 Phase 7 에서 표지로 더한다.
// 바꾸는 절차: 단어를 더하고 tests/unit/detect_sensitive_test.cpp 를 돌린 뒤 측정으로 오차단을 다시 잰다.
#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace prompt_airlock::detect::data {

// 호칭·직함. 바로 앞(공백 하나까지)에 한글 2~4음절이 있으면 특정 개인으로 본다("김가상 과장", "가상인님").
inline constexpr auto honorific_suffixes = std::to_array<std::u32string_view>({
    U"씨", U"님", U"과장", U"차장", U"부장", U"대리", U"주임", U"사원", U"팀장", U"실장", U"국장", U"주무관",
    U"사무관", U"환자", U"직원", U"민원인", U"학생", U"교수", U"선생",
});
// 호칭 앞이 이 말이면 특정 개인이 아니다("고객님", "회원님", 2026-10-18 결정, 측정에서 오차단 원인).
inline constexpr auto generic_addressees = std::to_array<std::u32string_view>({
    U"고객", U"회원", U"사용자", U"이용자", U"담당자", U"관리자", U"보호자", U"여러분", U"학부모", U"신청인",
    U"구매자", U"판매자", U"방문자", U"작성자", U"수신자", U"참석자",
});
inline constexpr std::size_t name_min_syllables = 2;
inline constexpr std::size_t name_max_syllables = 4;

// 자기 진술·가족 표현. 그 자체로 특정 개인을 가리킨다.
inline constexpr auto self_statements = std::to_array<std::u32string_view>({
    U"저는", U"제가", U"저의", U"나는", U"내가", U"본인은", U"본인이", U"본인의",
    U"우리 아이", U"우리 엄마", U"우리 아빠", U"제 남편", U"제 아내", U"저희 어머니", U"저희 아버지",
    U"i have", U"i am", U"my wife", U"my husband", U"my son", U"my daughter", U"my mother", U"my father",
});

}  // namespace prompt_airlock::detect::data
