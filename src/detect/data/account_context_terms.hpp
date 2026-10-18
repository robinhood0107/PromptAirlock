// 계좌 문맥어와 통화 단위. 문맥어가 가까이 있으면 6~34자리 숫자열을 계좌로 차단한다(ADR 0016 계좌 문맥 규칙).
// 원천: ADR 0016 예시(계좌, 입금, 예금주, 은행 이름, account, IBAN, 口座)를 넓혀 직접 작성한 사전. 확인일 2026-10-18.
// 금융기관 이름은 금융결제원 「참가기관별 CMS 계좌번호 체계」(2026.05.08)의 기관명에서 뽑았다.
// 바꾸는 절차: 단어를 더하고 tests/unit/detect_accounts_test.cpp 의 문맥 시험을 돌린 뒤 측정으로 오차단을 다시 잰다.
#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace prompt_airlock::detect::data {

// NFKC 뒤 글자로 쓴다. 영문은 대소문자를 구분하지 않는다(terms.hpp).
// "우리", "하나", "국민"처럼 일상어와 겹치는 은행 약칭은 넣지 않고 정식 이름만 넣는다.
inline constexpr auto account_context_terms = std::to_array<std::u32string_view>({
    // 한국어
    U"계좌", U"입금", U"출금", U"송금", U"이체", U"예금주", U"예금", U"통장", U"은행", U"뱅크",
    U"농협", U"수협", U"신협", U"새마을금고", U"우체국", U"저축은행", U"증권",
    U"국민은행", U"신한은행", U"우리은행", U"하나은행", U"기업은행", U"산업은행", U"씨티은행",
    U"카카오뱅크", U"토스뱅크", U"케이뱅크",
    // 영어
    U"account", U"acct", U"a/c", U"iban", U"bank", U"routing", U"sort code", U"bsb", U"ifsc", U"clabe",
    U"swift", U"bic", U"beneficiary", U"deposit", U"transfer", U"wire",
    // 일본어·중국어
    U"口座", U"振込", U"銀行", U"账户", U"账号",
});

// 숫자 바로 뒤(공백 하나까지)에 붙으면 금액으로 보고 문맥 규칙에서 뺀다(결정 #61).
inline constexpr auto currency_after = std::to_array<std::u32string_view>({
    U"원", U"만원", U"억원", U"천원", U"달러", U"엔", U"위안", U"유로",
    U"krw", U"usd", U"jpy", U"cny", U"eur", U"円", U"元"});
// 숫자 바로 앞에 붙으면 금액으로 본다.
inline constexpr auto currency_before = std::to_array<std::u32string_view>({U"$", U"₩", U"¥", U"€", U"krw", U"usd", U"eur"});

// 문맥 창(보기 글자 수). 초기값이고 5-3 측정으로 확정한다.
inline constexpr std::size_t account_context_window = 40;
// 문맥 규칙이 잡는 숫자열 길이.
inline constexpr std::size_t context_digits_min = 6;
inline constexpr std::size_t context_digits_max = 34;

}  // namespace prompt_airlock::detect::data
