#include "prompt_airlock/core/reason.hpp"

#include <utility>

namespace prompt_airlock::core {
namespace {

[[nodiscard]] ReasonCode reason_of(InputError error) noexcept {
    switch (error) {
        case InputError::InvalidUtf8: return ReasonCode::InvalidText;
        case InputError::EmptyDocument:
        case InputError::EmptyContent: return ReasonCode::EmptyPrompt;
        case InputError::TooLarge: return ReasonCode::PromptTooLarge;
        case InputError::ValueOutOfRange: return ReasonCode::ParameterOutOfRange;
        // 위치 오류는 입력이 아니라 core 를 부른 쪽의 결함이다.
        case InputError::EmptySpan:
        case InputError::OffsetOutOfRange:
        case InputError::NotCodepointBoundary:
        case InputError::SegmentOutOfRange: return ReasonCode::InternalError;
    }
    return ReasonCode::InternalError;
}

[[nodiscard]] ReasonCode reason_of(DetectError) noexcept { return ReasonCode::DetectorUnavailable; }
[[nodiscard]] ReasonCode reason_of(ProtectionError) noexcept { return ReasonCode::ProtectionUnavailable; }
[[nodiscard]] ReasonCode reason_of(VaultError) noexcept { return ReasonCode::ProtectionUnavailable; }
[[nodiscard]] ReasonCode reason_of(ResidualError) noexcept { return ReasonCode::DetectorUnavailable; }

[[nodiscard]] ReasonCode reason_of(RestoreError error) noexcept {
    switch (error) {
        case RestoreError::TokenNotFound: return ReasonCode::ResponseTokenUnresolved;
        case RestoreError::ResolverUnavailable: return ReasonCode::ProtectionUnavailable;
        case RestoreError::PlanMismatch: return ReasonCode::InternalError;
    }
    return ReasonCode::InternalError;
}

}  // namespace

std::string_view reason_code_name(ReasonCode code) noexcept {
    switch (code) {
        case ReasonCode::GradeClassified: return "grade_classified";
        case ReasonCode::GradeSensitive: return "grade_sensitive";
        case ReasonCode::GradeUnresolved: return "grade_unresolved";
        case ReasonCode::InvalidText: return "invalid_text";
        case ReasonCode::EmptyPrompt: return "empty_prompt";
        case ReasonCode::PromptTooLarge: return "prompt_too_large";
        case ReasonCode::TooManyEntities: return "too_many_entities";
        case ReasonCode::FieldNotAllowed: return "field_not_allowed";
        case ReasonCode::ContentPartNotAllowed: return "content_part_not_allowed";
        case ReasonCode::ParameterOutOfRange: return "parameter_out_of_range";
        case ReasonCode::StreamNotAllowed: return "stream_not_allowed";
        case ReasonCode::EntityBlocked: return "entity_blocked";
        case ReasonCode::EncodedTarget: return "encoded_target";
        case ReasonCode::OpaqueEncodedBlob: return "opaque_encoded_blob";
        case ReasonCode::ResidualFound: return "residual_found";
        case ReasonCode::ResponseTokenInLink: return "response_token_in_link";
        case ReasonCode::ResponseBlockedValue: return "response_blocked_value";
        case ReasonCode::ResponseTokenUnresolved: return "response_token_unresolved";
        case ReasonCode::DetectorUnavailable: return "detector_unavailable";
        case ReasonCode::ProtectionUnavailable: return "protection_unavailable";
        case ReasonCode::InternalError: return "internal_error";
    }
    return "internal_error";
}

ReasonCode to_reason(const CoreError& error) noexcept {
    return std::visit([](auto value) noexcept { return reason_of(value); }, error);
}

Rejection::Rejection(AuditRejection detail) noexcept : detail_(std::move(detail)) {}

Rejection Rejection::of(ReasonCode code) noexcept { return Rejection(AuditRejection{code, {}, {}, std::nullopt}); }

Rejection Rejection::from_error(CoreError error) noexcept {
    const auto code = to_reason(error);
    return Rejection(AuditRejection{code, {}, {}, error});
}

Rejection Rejection::with_findings(ReasonCode code, EntityTypeSet types, std::vector<AuditFinding> findings) noexcept {
    return Rejection(AuditRejection{code, types, std::move(findings), std::nullopt});
}

UserRejection Rejection::for_user() const noexcept {
    // 종류 집합은 차단 사유일 때만 보인다. 다른 사유에는 종류도 알리지 않는다.
    if (detail_.code == ReasonCode::EntityBlocked) {
        return UserRejection{detail_.code, detail_.blocked_types};
    }
    return UserRejection{detail_.code, {}};
}

}  // namespace prompt_airlock::core
