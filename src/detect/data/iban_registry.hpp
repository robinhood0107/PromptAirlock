// 이 파일은 tools/gen-iban-table.mjs 가 만든다. 직접 고치지 않는다.
// 원천: SWIFT IBAN Registry 텍스트판(국가 89개, SHA-256 앞 8자리 ad13d959, 확인일 2026-10-18).
// 구조 기호(SWIFT): n 숫자, a 영문 대문자, c 영숫자, 숫자는 자리 수, '!' 는 고정 길이.
// 바꾸는 절차: 새 Registry 를 official/formats/ 에 넣고 위 도구로 다시 만든 뒤 detect_accounts_test 를 돌린다.
#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace prompt_airlock::detect::data {

struct IbanCountry {
    std::string_view country;  // ISO 3166 두 글자
    std::uint8_t length;       // IBAN 전체 길이(국가 2 + 검증 2 + BBAN)
    std::string_view bban;     // BBAN 구조 기호
};

inline constexpr std::array<IbanCountry, 89> iban_countries = {{
    IbanCountry{"AD", 24, "4!n4!n12!c"},
    IbanCountry{"AE", 23, "3!n16!n"},
    IbanCountry{"AL", 28, "8!n16!c"},
    IbanCountry{"AT", 20, "5!n11!n"},
    IbanCountry{"AZ", 28, "4!a20!c"},
    IbanCountry{"BA", 20, "3!n3!n8!n2!n"},
    IbanCountry{"BE", 16, "3!n7!n2!n"},
    IbanCountry{"BG", 22, "4!a4!n2!n8!c"},
    IbanCountry{"BH", 22, "4!a14!c"},
    IbanCountry{"BI", 27, "5!n5!n11!n2!n"},
    IbanCountry{"BR", 29, "8!c5!n10!n1!c1!c"},
    IbanCountry{"BY", 28, "4!c4!n16!c"},
    IbanCountry{"CH", 21, "5!n12!c"},
    IbanCountry{"CR", 22, "4!n14!n"},
    IbanCountry{"CY", 28, "3!n5!n16!c"},
    IbanCountry{"CZ", 24, "4!n16!n"},
    IbanCountry{"DE", 22, "8!n10!n"},
    IbanCountry{"DJ", 27, "5!n5!n11!n2!n"},
    IbanCountry{"DK", 18, "4!n9!n1!n"},
    IbanCountry{"DO", 28, "4!c20!n"},
    IbanCountry{"EE", 20, "2!n14!n"},
    IbanCountry{"EG", 29, "4!n4!n17!n"},
    IbanCountry{"ES", 24, "4!n4!n1!n1!n10!n"},
    IbanCountry{"FI", 18, "3!n11!n"},
    IbanCountry{"FK", 18, "2!a12!n"},
    IbanCountry{"FO", 18, "4!n9!n1!n"},
    IbanCountry{"FR", 27, "5!n5!n11!c2!n"},
    IbanCountry{"GB", 22, "4!a6!n8!n"},
    IbanCountry{"GE", 22, "2!a16!n"},
    IbanCountry{"GI", 23, "4!a15!c"},
    IbanCountry{"GL", 18, "4!n9!n1!n"},
    IbanCountry{"GR", 27, "3!n4!n16!c"},
    IbanCountry{"GT", 28, "4!c20!c"},
    IbanCountry{"HN", 28, "4!a20!n"},
    IbanCountry{"HR", 21, "7!n10!n"},
    IbanCountry{"HU", 28, "3!n4!n1!n15!n1!n"},
    IbanCountry{"IE", 22, "4!a6!n8!n"},
    IbanCountry{"IL", 23, "3!n3!n13!n"},
    IbanCountry{"IQ", 23, "4!a3!n12!n"},
    IbanCountry{"IS", 26, "4!n2!n6!n10!n"},
    IbanCountry{"IT", 27, "1!a5!n5!n12!c"},
    IbanCountry{"JO", 30, "4!a4!n18!c"},
    IbanCountry{"KW", 30, "4!a22!c"},
    IbanCountry{"KZ", 20, "3!n13!c"},
    IbanCountry{"LB", 28, "4!n20!c"},
    IbanCountry{"LC", 32, "4!a24!c"},
    IbanCountry{"LI", 21, "5!n12!c"},
    IbanCountry{"LT", 20, "5!n11!n"},
    IbanCountry{"LU", 20, "3!n13!c"},
    IbanCountry{"LV", 21, "4!a13!c"},
    IbanCountry{"LY", 25, "3!n3!n15!n"},
    IbanCountry{"MC", 27, "5!n5!n11!c2!n"},
    IbanCountry{"MD", 24, "2!c18!c"},
    IbanCountry{"ME", 22, "3!n13!n2!n"},
    IbanCountry{"MK", 19, "3!n10!c2!n"},
    IbanCountry{"MN", 20, "4!n12!n"},
    IbanCountry{"MR", 27, "5!n5!n11!n2!n"},
    IbanCountry{"MT", 31, "4!a5!n18!c"},
    IbanCountry{"MU", 30, "4!a2!n2!n12!n3!n3!a"},
    IbanCountry{"NI", 28, "4!a20!n"},
    IbanCountry{"NL", 18, "4!a10!n"},
    IbanCountry{"NO", 15, "4!n6!n1!n"},
    IbanCountry{"OM", 23, "3!n16!c"},
    IbanCountry{"PK", 24, "4!a16!c"},
    IbanCountry{"PL", 28, "8!n16!n"},
    IbanCountry{"PS", 29, "4!a21!c"},
    IbanCountry{"PT", 25, "4!n4!n11!n2!n"},
    IbanCountry{"QA", 29, "4!a21!c"},
    IbanCountry{"RO", 24, "4!a16!c"},
    IbanCountry{"RS", 22, "3!n13!n2!n"},
    IbanCountry{"RU", 33, "9!n5!n15!c"},
    IbanCountry{"SA", 24, "2!n18!c"},
    IbanCountry{"SC", 31, "4!a2!n2!n16!n3!a"},
    IbanCountry{"SD", 18, "2!n12!n"},
    IbanCountry{"SE", 24, "3!n16!n1!n"},
    IbanCountry{"SI", 19, "5!n8!n2!n"},
    IbanCountry{"SK", 24, "4!n6!n10!n"},
    IbanCountry{"SM", 27, "1!a5!n5!n12!c"},
    IbanCountry{"SO", 23, "4!n3!n12!n"},
    IbanCountry{"ST", 25, "4!n4!n11!n2!n"},
    IbanCountry{"SV", 28, "4!a20!n"},
    IbanCountry{"TL", 23, "3!n14!n2!n"},
    IbanCountry{"TN", 24, "2!n3!n13!n2!n"},
    IbanCountry{"TR", 26, "5!n1!n16!c"},
    IbanCountry{"UA", 29, "6!n19!c"},
    IbanCountry{"VA", 22, "3!n15!n"},
    IbanCountry{"VG", 24, "4!a16!n"},
    IbanCountry{"XK", 20, "4!n10!n2!n"},
    IbanCountry{"YE", 30, "4!a4!n18!c"},
}};

}  // namespace prompt_airlock::detect::data
