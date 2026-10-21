// 고정 오류 응답(ADR 0020). Chat Completions 호환 error 객체에 사유 코드 이름과 차단 종류만 담는다.
// 위치, 원문, provider 오류 본문은 담을 자리가 없다.
#pragma once

#include <cstdint>
#include <string>

#include "prompt_airlock/core/reason.hpp"

namespace prompt_airlock::gateway {

// 처리 단계에 들어가기 전, HTTP 입구에서 끝나는 거절.
enum class EntryError : std::uint8_t {
    Unauthorized,          // 401: 출처 인증 실패
    TooManyFailures,       // 429: 인증 실패가 이어져 잠김
    NotFound,              // 404: 다른 경로
    MethodNotAllowed,      // 405: POST 가 아님
    BodyTooLarge,          // 413: 본문 상한 초과
    UnsupportedMediaType,  // 415: application/json 이 아님
    BadRequest,            // 400: HTTP 형식 오류
    Unavailable,           // 503: 처리 단계를 아직 쓸 수 없음
    ProviderFailed,        // 502: provider 연결 실패·시간 초과·오류 응답
};

struct JsonResponse {
    unsigned status;
    std::string body;  // JSON
};

[[nodiscard]] JsonResponse error_response(EntryError error);
[[nodiscard]] JsonResponse error_response(const core::UserRejection& rejection);

}  // namespace prompt_airlock::gateway
