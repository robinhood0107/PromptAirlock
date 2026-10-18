// 비밀 키 형식표: 공개 문서에 나온 키 접두와 최소 길이, PEM 개인 키 머리.
// 원천: 각 서비스 공개 문서의 키 형식(서비스 이름은 적지 않는다), PEM 은 RFC 7468, JWT 는 RFC 7519. 확인일 2026-10-18.
// 바꾸는 절차: 새 접두를 표에 더하고 tests/unit/detect_secrets_test.cpp 의 접두 순회 시험이 그 항목을 덮는지 본다.
// 항목은 지우지 않는다. 옛 형식 키도 계속 쓰인다.
#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace prompt_airlock::detect::data {

struct KeyPrefix {
    std::string_view prefix;   // 대소문자 그대로 비교한다
    std::size_t min_length;    // 접두 포함 전체 최소 길이
};

// 접두 뒤 문자는 영숫자와 '_', '-' 만 받는다(secrets.cpp is_key_char).
inline constexpr std::array<KeyPrefix, 21> key_prefixes = {{
    {"sk-", 20},          // 비밀 키 일반형
    {"sk_live_", 24},     // 결제 비밀 키
    {"sk_test_", 24},
    {"rk_live_", 24},     // 결제 제한 키
    {"ghp_", 36},         // 저장소 호스팅 토큰
    {"gho_", 36},
    {"ghu_", 36},
    {"ghs_", 36},
    {"ghr_", 36},
    {"github_pat_", 40},
    {"glpat-", 26},
    {"xoxb-", 20},        // 메신저 봇·사용자 토큰
    {"xoxp-", 20},
    {"xoxa-", 20},
    {"xoxs-", 20},
    {"AKIA", 20},         // 클라우드 접근 키 ID(대문자 영숫자 20자)
    {"ASIA", 20},
    {"AIza", 39},         // 클라우드 API 키
    {"hf_", 30},
    {"npm_", 40},
    {"glsa_", 40},
}};

// 이 말 뒤의 값은 접두가 없어도 키로 본다(대소문자 무시). 값은 16자 이상.
inline constexpr std::string_view bearer_word = "bearer";
inline constexpr std::size_t bearer_min_length = 16;

// JWT: "eyJ" 로 시작하는 base64url 세 조각, 조각마다 최소 길이.
inline constexpr std::string_view jwt_head = "eyJ";
inline constexpr std::size_t jwt_min_part = 10;

// PEM 개인 키. BEGIN 줄에 이 꼬리가 있으면 대응 END 까지(없으면 segment 끝까지) 차단한다.
inline constexpr std::string_view pem_begin = "-----BEGIN ";
inline constexpr std::string_view pem_end = "-----END ";
inline constexpr std::string_view pem_private_tail = "PRIVATE KEY-----";

}  // namespace prompt_airlock::detect::data
