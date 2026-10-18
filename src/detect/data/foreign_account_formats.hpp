// 외국 계좌 구조(IBAN 은 iban_registry.hpp). 구조가 맞으면 검증 자리와 관계없이 차단한다(ADR 0016).
// 원천: 각국 지급결제기관의 공식 원문은 확보하지 못했다(2026-10-18). 아래는 은행·지급 서비스의 공개 안내에서
// 서로 일치하는 형식이다. 공식 원문을 확보하면 항목별 출처를 바꾸고 시험 detect_accounts_test 를 다시 돌린다.
// 항목은 지우지 않는다. 차단을 줄이는 변경은 측정과 결정을 거친다.
#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace prompt_airlock::detect::data {

// 지점·은행 코드(앵커) 가까이에 계좌 숫자열이 있으면 둘 다 차단한다.
// groups: 앵커 숫자 묶음 길이(구분자 separator 로 이어짐). 0 이 아닌 separator 만 받는다.
struct AnchoredFormat {
    std::string_view name;                 // 시험 이름에 쓰는 식별자
    std::array<std::size_t, 3> groups;     // 사용하지 않는 칸은 0
    char32_t separator;
    std::size_t account_min;               // 계좌 숫자열 자릿수 범위
    std::size_t account_max;
};

// - 일본: 지점 3자리 + 계좌 7자리(全銀 형식, "123-4567890"), 우체국 기호 5자리 + 번호 8자리("12345-12345678").
//   이 둘은 앵커 없이 한 묶음 쌍으로 판정한다(jp_pairs).
// - 영국: sort code 2-2-2 + 계좌 8자리.
// - 캐나다: transit 5 + 기관 3("12345-678") + 계좌 7~12자리.
// - 호주: BSB 3-3("062-000") + 계좌 6~10자리.
inline constexpr std::array<AnchoredFormat, 3> anchored_formats = {{
    {"uk_sort_code", {2, 2, 2}, U'-', 8, 8},
    {"ca_transit", {5, 3, 0}, U'-', 7, 12},
    {"au_bsb", {3, 3, 0}, U'-', 6, 10},
}};

struct PairFormat {
    std::string_view name;
    std::size_t first;
    std::size_t second;
};
inline constexpr std::array<PairFormat, 2> jp_pairs = {{
    {"jp_branch_account", 3, 7},
    {"jp_postal_symbol_number", 5, 8},
}};

// 앵커와 계좌 숫자열 사이 최대 거리(보기 글자 수). 계좌 문맥 창과 같은 값으로 시작한다(측정으로 확정).
inline constexpr std::size_t anchor_window = 40;

// 미국 ABA routing number: 9자리, 가중치 3,7,1 반복 합이 10의 배수. 계좌는 4~17자리.
inline constexpr std::array<int, 9> aba_weights = {3, 7, 1, 3, 7, 1, 3, 7, 1};
inline constexpr std::size_t us_account_min = 4;
inline constexpr std::size_t us_account_max = 17;

// 인도 IFSC: 영문 4 + '0' + 영숫자 6. 계좌는 9~18자리.
inline constexpr std::size_t in_account_min = 9;
inline constexpr std::size_t in_account_max = 18;

// 멕시코 CLABE: 18자리, 앞 17자리에 가중치 3,7,1 반복, 검증 자리 = (10 - 합 % 10) % 10.
inline constexpr std::size_t clabe_length = 18;

// 중국 은행카드(銀聯): 62 로 시작하는 16~19자리.
inline constexpr std::string_view cn_card_prefix = "62";
inline constexpr std::size_t cn_card_min = 16;
inline constexpr std::size_t cn_card_max = 19;

}  // namespace prompt_airlock::detect::data
