#pragma once

#include <cstdint>
#include <variant>

namespace prompt_airlock::core {

// 입력 텍스트·위치·값 검증 실패.
enum class InputError : std::uint8_t {
    InvalidUtf8,
    EmptySpan,
    OffsetOutOfRange,
    NotCodepointBoundary,
    SegmentOutOfRange,
    EmptyDocument,
    EmptyContent,
    TooLarge,
    ValueOutOfRange,
};

// detector 실패. Phase 5·7·9 의 detector 와 worker 가 만든다.
enum class DetectError : std::uint8_t { Unavailable, Overloaded, Timeout, InvalidSpan };

// 가명 보호 단계 실패. issuer 가 돌려준 token 의 이중 확인 실패도 여기에 든다.
enum class ProtectionError : std::uint8_t {
    IssuerUnavailable,
    MalformedToken,
    LabelMismatch,
    InconsistentAssignment,
    TokenLeaksValue,
    CountMismatch,
};

// Vault 연결 실패. Phase 6 의 client 가 만든다.
enum class VaultError : std::uint8_t { Unavailable, Timeout, ScopeNotFound, ProtocolMismatch };

// 잔여 검사 입력 실패.
enum class ResidualError : std::uint8_t { InvalidSpan };

// 응답 복원 실패.
enum class RestoreError : std::uint8_t { TokenNotFound, ResolverUnavailable, PlanMismatch };

using CoreError = std::variant<InputError, DetectError, ProtectionError, VaultError, ResidualError, RestoreError>;

}  // namespace prompt_airlock::core
