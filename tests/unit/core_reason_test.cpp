#include "prompt_airlock/core/reason.hpp"

#include <gtest/gtest.h>

#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace pc = prompt_airlock::core;
using pc::ReasonCode;

// 사용자용 거절은 위치를 담는 컨테이너가 없는 작은 값이다.
static_assert(std::is_trivially_copyable_v<pc::UserRejection>);
static_assert(sizeof(pc::UserRejection) <= 8);

namespace {

const std::vector<ReasonCode>& all_codes() {
    static const std::vector<ReasonCode> codes = {
        ReasonCode::GradeClassified,      ReasonCode::GradeSensitive,      ReasonCode::GradeUnresolved,
        ReasonCode::InvalidText,          ReasonCode::EmptyPrompt,         ReasonCode::PromptTooLarge,
        ReasonCode::TooManyEntities,      ReasonCode::FieldNotAllowed,     ReasonCode::ContentPartNotAllowed,
        ReasonCode::ParameterOutOfRange,  ReasonCode::StreamNotAllowed,    ReasonCode::EntityBlocked,
        ReasonCode::EncodedTarget,        ReasonCode::OpaqueEncodedBlob,   ReasonCode::ResidualFound,
        ReasonCode::ResponseTokenInLink,  ReasonCode::ResponseBlockedValue, ReasonCode::ResponseTokenUnresolved,
        ReasonCode::DetectorUnavailable,  ReasonCode::ProtectionUnavailable, ReasonCode::InternalError,
    };
    return codes;
}

pc::ByteSpan span(std::size_t begin, std::size_t end) {
    return *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{end});
}

}  // namespace

TEST(CoreReason, CodeValuesAreFixed) {
    EXPECT_EQ(std::to_underlying(ReasonCode::GradeClassified), 100);
    EXPECT_EQ(std::to_underlying(ReasonCode::PromptTooLarge), 202);
    EXPECT_EQ(std::to_underlying(ReasonCode::EntityBlocked), 400);
    EXPECT_EQ(std::to_underlying(ReasonCode::ResponseTokenInLink), 500);
    EXPECT_EQ(std::to_underlying(ReasonCode::InternalError), 902);
}

TEST(CoreReason, NamesAreUniqueSnakeCase) {
    std::set<std::string> seen;
    for (const auto code : all_codes()) {
        const auto name = pc::reason_code_name(code);
        ASSERT_FALSE(name.empty());
        for (const char c : name) {
            EXPECT_TRUE((c >= 'a' && c <= 'z') || c == '_') << name;
        }
        EXPECT_TRUE(seen.insert(std::string(name)).second) << name;
    }
    EXPECT_EQ(seen.size(), all_codes().size());
}

TEST(CoreReason, EveryErrorMapsToRejectionCode) {
    using pc::InputError;
    EXPECT_EQ(pc::to_reason(InputError::InvalidUtf8), ReasonCode::InvalidText);
    EXPECT_EQ(pc::to_reason(InputError::EmptyDocument), ReasonCode::EmptyPrompt);
    EXPECT_EQ(pc::to_reason(InputError::EmptyContent), ReasonCode::EmptyPrompt);
    EXPECT_EQ(pc::to_reason(InputError::TooLarge), ReasonCode::PromptTooLarge);
    EXPECT_EQ(pc::to_reason(InputError::ValueOutOfRange), ReasonCode::ParameterOutOfRange);
    for (const auto e : {InputError::EmptySpan, InputError::OffsetOutOfRange, InputError::NotCodepointBoundary,
                         InputError::SegmentOutOfRange}) {
        EXPECT_EQ(pc::to_reason(e), ReasonCode::InternalError);
    }
    for (const auto e : {pc::DetectError::Unavailable, pc::DetectError::Overloaded, pc::DetectError::Timeout,
                         pc::DetectError::InvalidSpan}) {
        EXPECT_EQ(pc::to_reason(e), ReasonCode::DetectorUnavailable);
    }
    for (const auto e : {pc::ProtectionError::IssuerUnavailable, pc::ProtectionError::MalformedToken,
                         pc::ProtectionError::LabelMismatch, pc::ProtectionError::InconsistentAssignment,
                         pc::ProtectionError::TokenLeaksValue, pc::ProtectionError::CountMismatch}) {
        EXPECT_EQ(pc::to_reason(e), ReasonCode::ProtectionUnavailable);
    }
    for (const auto e : {pc::VaultError::Unavailable, pc::VaultError::Timeout, pc::VaultError::ScopeNotFound,
                         pc::VaultError::ProtocolMismatch}) {
        EXPECT_EQ(pc::to_reason(e), ReasonCode::ProtectionUnavailable);
    }
    EXPECT_EQ(pc::to_reason(pc::ResidualError::InvalidSpan), ReasonCode::DetectorUnavailable);
    EXPECT_EQ(pc::to_reason(pc::RestoreError::TokenNotFound), ReasonCode::ResponseTokenUnresolved);
    EXPECT_EQ(pc::to_reason(pc::RestoreError::ResolverUnavailable), ReasonCode::ProtectionUnavailable);
    EXPECT_EQ(pc::to_reason(pc::RestoreError::PlanMismatch), ReasonCode::InternalError);
}

TEST(CoreReason, OutOfRangeErrorFailsClosed) {
    EXPECT_EQ(pc::to_reason(static_cast<pc::InputError>(250)), ReasonCode::InternalError);
    EXPECT_EQ(pc::to_reason(static_cast<pc::RestoreError>(250)), ReasonCode::InternalError);
}

TEST(CoreReason, UserViewHasNoLocation) {
    pc::EntityTypeSet types;
    types.insert(pc::EntityType::BankAccount);
    std::vector<pc::AuditFinding> findings{
        pc::EntityFinding{pc::SegmentIndex{2}, span(4, 18), pc::EntityType::BankAccount, pc::DetectorKind::Pattern}};
    const auto rejection = pc::Rejection::with_findings(ReasonCode::EntityBlocked, types, std::move(findings));

    const auto user = rejection.for_user();
    EXPECT_EQ(user.code, ReasonCode::EntityBlocked);
    EXPECT_EQ(user.blocked_types, types);

    const auto& audit = rejection.for_audit();
    ASSERT_EQ(audit.findings.size(), 1U);
    const auto& finding = std::get<pc::EntityFinding>(audit.findings.front());
    EXPECT_EQ(finding.segment, pc::SegmentIndex{2});
    EXPECT_EQ(finding.span, span(4, 18));
}

TEST(CoreReason, TypesHiddenUnlessBlocked) {
    pc::EntityTypeSet types;
    types.insert(pc::EntityType::Person);
    const auto rejection = pc::Rejection::with_findings(ReasonCode::ResidualFound, types, {});
    EXPECT_TRUE(rejection.for_user().blocked_types.empty());
    EXPECT_EQ(rejection.for_audit().blocked_types, types);
}

TEST(CoreReason, FromErrorKeepsCauseForAuditOnly) {
    const auto rejection = pc::Rejection::from_error(pc::DetectError::Timeout);
    EXPECT_EQ(rejection.code(), ReasonCode::DetectorUnavailable);
    EXPECT_EQ(rejection.for_user(), (pc::UserRejection{ReasonCode::DetectorUnavailable, {}}));
    ASSERT_TRUE(rejection.for_audit().cause.has_value());
    EXPECT_EQ(std::get<pc::DetectError>(*rejection.for_audit().cause), pc::DetectError::Timeout);
    const auto plain = pc::Rejection::of(ReasonCode::GradeSensitive);
    EXPECT_FALSE(plain.for_audit().cause.has_value());
}
