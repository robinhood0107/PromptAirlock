// 국내 번호 형식표: 전화번호 대역, 여권번호 종류 문자, 운전면허 지역.
// 바꾸는 절차: 1) 아래 원천을 다시 확인한다 2) 표를 고친다 3) tests/unit/detect_formats_test.cpp 의
//   해당 사례를 고친다 4) 측정 도구로 오차단을 다시 잰다 5) docs/adr/0016 변경 조건에 해당하는지 본다.
// 항목은 지우지 않는다. 옛 번호 형식도 계속 쓰이므로 남긴다.
#pragma once

#include <array>
#include <string_view>

namespace prompt_airlock::detect::data {

// 전화번호. 원천: 전기통신번호관리세칙(과학기술정보통신부 고시 제2021-93호, 시행 2021.12.7.) 제8조·제20조,
// 확인일 2026-10-18, 본문 저장본 SHA-256 앞 8자리 85aef976.
// - 제20조④1: 이동전화번호는 010-ABYY-YYYY(A=2~9). 010 은 국번 첫 자리가 2~9 인 8자리만 받는다.
// - 제8조③3가: 옛 이동전화 식별번호 01Y(Y=0,1,6,7,8,9). 국번 3~4자리 + 가입자 4자리.
// - 제8조③8: 인터넷전화 070. 제8조④2: 개인번호서비스 050(뒤 한 자리를 더해 050X).
inline constexpr std::array<std::string_view, 5> legacy_mobile_prefixes = {"011", "016", "017", "018", "019"};

// 지역번호. 세칙 제7조③의 표는 웹 본문에서 이미지로 나와 텍스트로 대조하지 못했다(남은 일: 별표 원문 대조).
// 널리 쓰이는 번호권별 지역번호를 쓴다. 바뀌면 이 표와 시험 KoreanPhone 사례를 함께 고친다.
inline constexpr std::array<std::string_view, 17> area_codes = {
    "02",  "031", "032", "033", "041", "042", "043", "044", "051",
    "052", "053", "054", "055", "061", "062", "063", "064"};

// 여권번호 종류 문자. 원천: 외교부 여권안내 「차세대 전자여권 안내」(passport.go.kr, menuPos=60, 확인일 2026-10-18).
// 여권번호 체계: 옛 형식 영문 1 + 숫자 8(예 M12345678), 차세대 형식 영문 1 + 숫자 3 + 영문 1 + 숫자 4(예 M123A4567).
// 공식 예시는 M 뿐이다. 다른 종류 문자(S, R, O, D)는 공식 원천이 없어 보조 자료 기준으로 넣는다(차단을 넓히는 방향).
inline constexpr std::string_view passport_type_letters = "MSROD";

// 운전면허번호: 지역 2 + 발급연도 2 + 일련번호 6 + 2자리. 원천: 주모로코대사관 공지 「운전면허번호 지역표기 방식
// 변경 안내」(2014-04-14, overseas.mofa.go.kr seq=1063675, 확인일 2026-10-18). 예: 서울 95-255933-61 → 11-95-255933-61.
// 공지의 지역 번호는 11~23, 25, 26 이다. 이후 생긴 번호를 놓치지 않도록 11~28 범위를 받는다(차단을 넓히는 방향).
inline constexpr int license_region_min = 11;
inline constexpr int license_region_max = 28;

// 2014년 이전 면허증의 지역 글자 표기. 공지 목록에 광주를 더했다(공지는 광주를 전남으로 묶음).
inline constexpr std::array<std::u32string_view, 16> license_region_names = {
    U"서울", U"부산", U"경기", U"강원", U"충북", U"충남", U"전북", U"전남",
    U"경북", U"경남", U"제주", U"대구", U"인천", U"대전", U"울산", U"광주"};

// 숫자만 붙여 쓴 12자리 면허번호는 업무 숫자(시각 등)와 겹치므로, 앞쪽에 이 말이 있을 때만 받는다.
inline constexpr std::u32string_view license_keyword = U"면허";
inline constexpr std::size_t license_keyword_window = 20;

}  // namespace prompt_airlock::detect::data
