// 인증 정보(Credential) 표지어와 계정 문맥어(ADR 0016).
// 원천: ADR 0016(비밀번호, PIN, 인증번호, OTP, password, パスワード, 密码), 2023 국가정보원 외부 언어모델 활용 보안
// 가이드라인 p.30(사용자 이름, 비밀번호, 인증 코드)을 넓혀 직접 작성한 사전. 확인일 2026-10-18.
// 바꾸는 절차: 단어를 더하고 tests/unit/detect_credentials_test.cpp 를 돌린 뒤 측정으로 오차단을 다시 잰다.
#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace prompt_airlock::detect::data {

// 이 말 뒤에 구분(':' '=' 또는 은/는/이/가/is)과 값이 오면 값을 차단한다.
inline constexpr auto secret_markers = std::to_array<std::u32string_view>({
    U"비밀번호", U"비번", U"암호", U"패스워드", U"핀번호", U"인증번호", U"인증코드", U"보안코드", U"일회용비밀번호",
    U"password", U"passwd", U"pwd", U"pw", U"pass", U"passcode", U"passphrase", U"pin", U"otp", U"secret",
    U"パスワード", U"暗証番号", U"密码", U"口令",
});

// 비밀 표지어와 짝으로 쓰는 계정 이름 표지어. 비밀 값이 함께 있을 때만 이 값도 차단한다(앞 40자 안).
inline constexpr auto user_markers = std::to_array<std::u32string_view>({
    U"아이디", U"계정", U"사용자명", U"id", U"user", U"username", U"login", U"userid", U"ユーザー名", U"用户名",
});

// 계정 문맥어. 이 말 가까이(40자)에 무작위 문자열(8자 이상, 문자 종류 3개 이상)이 있으면 차단한다.
inline constexpr auto account_markers = std::to_array<std::u32string_view>({
    U"계정", U"아이디", U"로그인", U"접속", U"account", U"login", U"sign in", U"credential", U"credentials",
});

// 무작위성 판정에서 뺄 흔한 단어(영문 부분을 소문자로 비교). 제품명·연도 조합 같은 일반 표기를 줄인다.
inline constexpr auto common_words = std::to_array<std::string_view>({
    "windows", "office", "android", "iphone", "galaxy", "version", "update", "release", "python", "java",
});

// 표지어와 구분 사이에 낄 수 있는 말("OTP 번호는", "PIN 코드:"). #146 댓글(2026-10-30)에서 찾은 빈틈.
inline constexpr auto marker_suffixes = std::to_array<std::u32string_view>({U"번호", U"코드", U"값", U"number", U"code"});

// 표지어 뒤 구분으로 받는 한국어 조사와 영어 "is".
inline constexpr auto marker_particles = std::to_array<std::u32string_view>({U"은", U"는", U"이", U"가", U"is"});

inline constexpr std::size_t credential_window = 40;
inline constexpr std::size_t credential_value_max = 128;
inline constexpr std::size_t random_min_length = 8;
inline constexpr std::size_t random_min_classes = 3;
// HTTP Basic 인증 값(base64) 최소 길이.
inline constexpr std::size_t basic_min_length = 8;

}  // namespace prompt_airlock::detect::data
