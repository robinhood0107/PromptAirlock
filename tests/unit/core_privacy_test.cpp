#include "prompt_airlock/core/privacy.hpp"
#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/research.hpp"

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "fake_vault.hpp"

namespace pc = prompt_airlock::core;
using pc::EntityType;
using pc::ReasonCode;

static_assert(pc::TokenIssuer<pa_test::FakeVault>);

namespace {

// 합성 문장. "가상인"(9 byte)이 두 번, 합성 전화번호가 한 번 나온다.
const std::string text = "가상인 과장, 가상인 010-0000-0000";
constexpr std::size_t name1 = 0, name2 = 18, phone = 28;

pc::EntitySpan entity(std::size_t begin, std::size_t end, EntityType type) {
    const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{end});
    return *pc::EntitySpan::make(text, pc::SegmentIndex{0}, span, type, pc::DetectorKind::Pattern);
}

std::vector<pc::EntitySpan> default_detections() {
    return {entity(name1, name1 + 9, EntityType::Person), entity(name2, name2 + 9, EntityType::Person),
            entity(phone, phone + 13, EntityType::KoreanPhone)};
}

pc::PolicyCheckedPrompt checked(const pc::Policy& policy,
                                const std::vector<pc::EntitySpan>& detected = default_detections()) {
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts));
    auto raw = pc::RawPrompt::create(*std::move(builder).build(),
                                     *pc::RequestParams::create({}, pc::OutputTokenCap::standard()),
                                     *pc::resolve_grade(pc::GradePolicy::OOnly, {}));
    return *pc::check_policy(std::move(raw), detected, policy);
}

std::string protected_text(const pc::ProtectedPrompt& prompt) {
    return std::string(prompt.document().segments()[0].text());
}

pc::Token token(std::string_view label, std::string_view random) {
    return *pc::parse_token(std::string(pc::token_open) + std::string(label) + "_" + std::string(random) +
                            std::string(pc::token_close));
}

// 정해진 token 을 차례로 돌려주는 발급기(규칙 위반을 흉내 낸다).
struct ScriptedIssuer {
    std::vector<pc::Token> tokens;
    std::size_t next = 0;
    std::expected<pc::Token, pc::ProtectionError> issue(EntityType, std::string_view) {
        if (next >= tokens.size()) {
            return std::unexpected(pc::ProtectionError::IssuerUnavailable);
        }
        return tokens[next++];
    }
};

pc::ProtectionError protection_error(const std::expected<pc::ProtectedPrompt, pc::Rejection>& result) {
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ReasonCode::ProtectionUnavailable);
    return std::get<pc::ProtectionError>(*result.error().for_audit().cause);
}

}  // namespace

TEST(CorePrivacy, UniquePseudonymReplacesEveryTarget) {
    pa_test::FakeVault vault(1);
    const auto prompt = pc::protect(checked(pc::Policy::standard()), vault);
    ASSERT_TRUE(prompt);
    const auto out = protected_text(*prompt);
    EXPECT_EQ(out.find("가상인"), std::string::npos);
    EXPECT_EQ(out.find("010-0000-0000"), std::string::npos);
    EXPECT_EQ(vault.issued(), 2U);  // 같은 이름은 같은 token

    const auto found = pc::scan_tokens(out);
    ASSERT_EQ(found.size(), 3U);
    EXPECT_EQ(found[0].token, found[1].token);
    EXPECT_NE(found[0].token, found[2].token);
    ASSERT_EQ(prompt->replacements().size(), 3U);
    for (std::size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(prompt->replacements()[i].span, found[i].span);
    }
}

TEST(CorePrivacy, ResearchStrategiesRewriteWithoutTokens) {
    const auto key = pc::make_research_only();
    pa_test::FakeVault vault(2);

    const auto redacted = pc::protect(checked(pc::Policy::research(key, pc::PrivacyStrategy::redaction())), vault);
    ASSERT_TRUE(redacted);
    EXPECT_EQ(protected_text(*redacted), "⟦REDACTED⟧ 과장, ⟦REDACTED⟧ ⟦REDACTED⟧");

    const auto masked = pc::protect(checked(pc::Policy::research(key, pc::PrivacyStrategy::type_mask())), vault);
    ASSERT_TRUE(masked);
    EXPECT_EQ(protected_text(*masked), "⟦PERSON⟧ 과장, ⟦PERSON⟧ ⟦KOREAN_PHONE⟧");
    EXPECT_TRUE(pc::scan_tokens(protected_text(*masked)).empty());  // 표지는 token 모양이 아니다

    const auto none =
        pc::protect(checked(pc::Policy::research(key, pc::PrivacyStrategy::no_protection(key))), vault);
    ASSERT_TRUE(none);
    EXPECT_EQ(protected_text(*none), text);
    EXPECT_TRUE(none->replacements().empty());
    EXPECT_EQ(vault.issued(), 0U);
}

TEST(CorePrivacy, RejectsIssuerViolations) {
    const auto person_a = token("PERSON", "AAAAAAAAAA");
    const auto person_b = token("PERSON", "BBBBBBBBBB");
    const auto phone_c = token("KOREAN_PHONE", "CCCCCCCCCC");

    ScriptedIssuer same_value_two_tokens{{person_a, person_b, phone_c}};
    EXPECT_EQ(protection_error(pc::protect(checked(pc::Policy::standard()), same_value_two_tokens)),
              pc::ProtectionError::InconsistentAssignment);

    ScriptedIssuer wrong_label{{person_a, person_a, token("EMAIL", "CCCCCCCCCC")}};
    EXPECT_EQ(protection_error(pc::protect(checked(pc::Policy::standard()), wrong_label)),
              pc::ProtectionError::LabelMismatch);

    ScriptedIssuer leaking{{person_a, person_a, token("KOREAN_PHONE", "XX0100000X")}};
    EXPECT_EQ(protection_error(pc::protect(checked(pc::Policy::standard()), leaking)),
              pc::ProtectionError::TokenLeaksValue);

    ScriptedIssuer runs_out{{person_a}};
    EXPECT_EQ(protection_error(pc::protect(checked(pc::Policy::standard()), runs_out)),
              pc::ProtectionError::IssuerUnavailable);

    EXPECT_EQ(protection_error(pc::apply_protection(checked(pc::Policy::standard()), {})),
              pc::ProtectionError::CountMismatch);
}

TEST(CorePrivacy, RejectsOneTokenForTwoValues) {
    // "가상인"과 "과장"(byte 10..16)을 서로 다른 이름으로 탐지했는데 같은 token 을 주면 거절한다.
    const std::vector<pc::EntitySpan> two_names{entity(name1, name1 + 9, EntityType::Person),
                                                entity(10, 16, EntityType::Person)};
    const auto person_a = token("PERSON", "AAAAAAAAAA");
    EXPECT_EQ(protection_error(pc::apply_protection(checked(pc::Policy::standard(), two_names), {person_a, person_a})),
              pc::ProtectionError::InconsistentAssignment);
    EXPECT_TRUE(pc::apply_protection(checked(pc::Policy::standard(), two_names),
                                     {person_a, token("PERSON", "BBBBBBBBBB")}));
}
