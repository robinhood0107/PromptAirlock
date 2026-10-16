#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/prompt.hpp"
#include "prompt_airlock/core/provider_boundary.hpp"

#include <gtest/gtest.h>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace pc = prompt_airlock::core;
using pc::EntityType;
using pc::ReasonCode;

// 네 단계 모두: 복사 불가, 넘기기는 noexcept, 열쇠 없이 만들 수 없음.
template <class State>
constexpr bool sealed_state = !std::is_copy_constructible_v<State> && !std::is_copy_assignable_v<State> &&
                              std::is_nothrow_move_constructible_v<State> && !std::is_default_constructible_v<State>;
static_assert(sealed_state<pc::RawPrompt>);
static_assert(sealed_state<pc::PolicyCheckedPrompt>);
static_assert(sealed_state<pc::ProtectedPrompt>);
static_assert(sealed_state<pc::VerifiedPrompt>);
static_assert(!std::is_constructible_v<pc::PolicyCheckedPrompt, pc::RawPrompt, std::vector<pc::MergedEntity>>);
static_assert(!std::is_constructible_v<pc::VerifiedPrompt, pc::ProtectedPrompt>);
static_assert(sealed_state<pc::ProviderRequest>);
// 외부 요청은 검증 완료 단계에서만 만들 수 있다. 빌드 실패 자체는 tests/compile_fail 이 확인한다.
static_assert(std::is_invocable_v<decltype(&pc::make_provider_request), const pc::VerifiedPrompt&>);

namespace {

// 합성 문장. 탐지 위치는 이 텍스트 기준이다.
const std::string& sentence() {
    static const std::string text(600, 'x');
    return text;
}

pc::RawPrompt raw_prompt() {
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(sentence()));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts))
        .add_stop(pc::SensitiveText::copy_of("끝"));
    auto document = std::move(builder).build();
    auto params = pc::RequestParams::create({}, pc::OutputTokenCap::standard());
    auto grade = pc::resolve_grade(pc::GradePolicy::OOnly, {});
    return pc::RawPrompt::create(std::move(*document), *params, *grade);
}

pc::EntitySpan entity(std::size_t begin, std::size_t end, EntityType type) {
    const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{end});
    return *pc::EntitySpan::make(sentence(), pc::SegmentIndex{0}, span, type, pc::DetectorKind::Pattern);
}

}  // namespace

TEST(CorePrompt, TokenizeOnlyPassesWithMergedEntities) {
    const std::vector<pc::EntitySpan> detected{entity(0, 5, EntityType::Person), entity(3, 9, EntityType::Email),
                                               entity(20, 30, EntityType::KoreanPhone)};
    const auto checked = pc::check_policy(raw_prompt(), detected, pc::Policy::standard());
    ASSERT_TRUE(checked);
    ASSERT_EQ(checked->entities().size(), 2U);
    EXPECT_EQ(checked->entities()[0].label_type, EntityType::Email);
    EXPECT_EQ(checked->document().segments().size(), 2U);
    EXPECT_EQ(checked->grade().origin(), pc::GradeOrigin::SourceDefault);
}

TEST(CorePrompt, EveryBlockTypeRejectsWholeRequest) {
    for (const auto type : pc::all_entity_types()) {
        if (pc::default_action(type) != pc::Action::Block) {
            continue;
        }
        const std::vector<pc::EntitySpan> detected{entity(0, 5, EntityType::Person), entity(40, 50, type)};
        const auto checked = pc::check_policy(raw_prompt(), detected, pc::Policy::standard());
        ASSERT_FALSE(checked) << pc::entity_type_name(type);
        const auto user = checked.error().for_user();
        EXPECT_EQ(user.code, ReasonCode::EntityBlocked);
        EXPECT_EQ(user.blocked_types.size(), 1U);
        EXPECT_TRUE(user.blocked_types.contains(type));
        const auto& audit = checked.error().for_audit();
        ASSERT_EQ(audit.findings.size(), 1U);
        EXPECT_EQ(std::get<pc::EntityFinding>(audit.findings.front()).span, entity(40, 50, type).span());
    }
}

TEST(CorePrompt, EntityLimitCountsBeforeMerge) {
    std::vector<pc::EntitySpan> detected;
    for (std::size_t i = 0; i < pc::max_entities; ++i) {
        detected.push_back(entity(i, i + 1, EntityType::Person));
    }
    EXPECT_TRUE(pc::check_policy(raw_prompt(), detected, pc::Policy::standard()));
    detected.push_back(entity(0, 1, EntityType::Person));
    const auto over = pc::check_policy(raw_prompt(), detected, pc::Policy::standard());
    ASSERT_FALSE(over);
    EXPECT_EQ(over.error().code(), ReasonCode::TooManyEntities);
}

TEST(CorePrompt, RejectsSpansThatDoNotMatchDocument) {
    // detector 가 다른 segment 번호나 다른 텍스트 기준 위치를 내면 믿지 않는다.
    const std::string longer(2000, 'x');
    const auto far = *pc::ByteSpan::make(pc::Utf8ByteOffset{1000}, pc::Utf8ByteOffset{1010});
    const std::vector<pc::EntitySpan> wrong_offset{
        *pc::EntitySpan::make(longer, pc::SegmentIndex{0}, far, EntityType::Person, pc::DetectorKind::Ner)};
    const std::vector<pc::EntitySpan> wrong_segment{
        *pc::EntitySpan::make(longer, pc::SegmentIndex{7}, far, EntityType::Person, pc::DetectorKind::Ner)};

    for (const auto& detected : {wrong_offset, wrong_segment}) {
        const auto checked = pc::check_policy(raw_prompt(), detected, pc::Policy::standard());
        ASSERT_FALSE(checked);
        EXPECT_EQ(checked.error().code(), ReasonCode::DetectorUnavailable);
        EXPECT_EQ(std::get<pc::DetectError>(*checked.error().for_audit().cause), pc::DetectError::InvalidSpan);
    }
}

TEST(CorePrompt, NoDetectionsPassesUnchanged) {
    const auto checked = pc::check_policy(raw_prompt(), {}, pc::Policy::standard());
    ASSERT_TRUE(checked);
    EXPECT_TRUE(checked->entities().empty());
    EXPECT_EQ(checked->params().max_output_tokens(), 4096U);
}
