#include "prompt_airlock/core/restore.hpp"

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "fake_vault.hpp"

namespace pc = prompt_airlock::core;
using pc::ReasonCode;

static_assert(pc::TokenResolver<pa_test::FakeVault>);
static_assert(!std::is_copy_constructible_v<pc::CheckedResponse>);
static_assert(!std::is_constructible_v<pc::CheckedResponse, pc::SensitiveText>);

namespace {

pc::CheckedResponse checked(const std::string& text, const std::vector<pc::EntitySpan>& findings = {}) {
    return *pc::check_response(pc::SensitiveText::copy_of(text), findings);
}

// 복원기를 몇 번 불렀는지 센다.
struct CountingResolver {
    pa_test::FakeVault& vault;
    int calls = 0;
    std::expected<pc::SensitiveText, pc::RestoreError> resolve(const pc::Token& token) {
        ++calls;
        return vault.resolve(token);
    }
};

ReasonCode restore_error(const std::string& response, pa_test::FakeVault& vault) {
    auto checked_response = checked(response);
    const auto plan = pc::plan_restore(checked_response);
    if (!plan) {
        return plan.error().code();
    }
    const auto restored = pc::apply_restore(std::move(checked_response), *plan, vault);
    return restored ? ReasonCode::InternalError : restored.error().code();
}

}  // namespace

TEST(CoreRestore, RestoresExactTokensOnce) {
    pa_test::FakeVault vault(3);
    const auto person = *vault.issue(pc::EntityType::Person, "가상인");
    const auto email = *vault.issue(pc::EntityType::Email, "user1@example.invalid");
    const std::string response =
        std::string(person.text()) + " 과장님, " + std::string(person.text()) + " 님께 " + std::string(email.text()) +
        " 로 보냈습니다.";
    auto checked_response = checked(response);
    const auto plan = pc::plan_restore(checked_response);
    ASSERT_TRUE(plan);
    CountingResolver resolver{vault};
    const auto restored = pc::apply_restore(std::move(checked_response), *plan, resolver);
    ASSERT_TRUE(restored);
    EXPECT_EQ(restored->view(), "가상인 과장님, 가상인 님께 user1@example.invalid 로 보냈습니다.");
    EXPECT_EQ(resolver.calls, 2);
}

TEST(CoreRestore, ModifiedTokensStayAsIs) {
    pa_test::FakeVault vault(3);
    const auto person = *vault.issue(pc::EntityType::Person, "가상인");
    std::string lowered(person.text());
    for (auto& c : lowered) {
        c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
    }
    auto checked_response = checked("답: " + lowered);
    const auto plan = pc::plan_restore(checked_response);
    ASSERT_TRUE(plan);
    EXPECT_TRUE(plan->occurrences.empty());
    const auto restored = pc::apply_restore(std::move(checked_response), *plan, vault);
    EXPECT_EQ(restored->view(), "답: " + lowered);  // 추측해서 고치지 않는다
}

TEST(CoreRestore, TokenFromAnotherScopeRejectsWholeResponse) {
    pa_test::FakeVault this_request(3);
    pa_test::FakeVault other_request(4);
    const auto mine = *this_request.issue(pc::EntityType::Person, "가상인");
    const auto foreign = *other_request.issue(pc::EntityType::Person, "다른이");
    EXPECT_EQ(restore_error(std::string(mine.text()) + " " + std::string(foreign.text()), this_request),
              ReasonCode::ResponseTokenUnresolved);
}

TEST(CoreRestore, TokenInLinkRejectsWholeResponse) {
    pa_test::FakeVault vault(3);
    const auto person = *vault.issue(pc::EntityType::Person, "가상인");
    EXPECT_EQ(restore_error("![x](https://example.invalid/?u=" + std::string(person.text()) + ")", vault),
              ReasonCode::ResponseTokenInLink);
}

TEST(CoreRestore, ResponseCheckRejectsBlockedValues) {
    const std::string response = "합성 번호는 000000-0000000 입니다.";
    const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{17}, pc::Utf8ByteOffset{31});
    const std::vector<pc::EntitySpan> rrn{
        *pc::EntitySpan::make(response, pc::SegmentIndex{0}, span, pc::EntityType::KoreanRrn, pc::DetectorKind::Pattern)};
    const auto result = pc::check_response(pc::SensitiveText::copy_of(response), rrn);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().for_user(), (pc::UserRejection{ReasonCode::ResponseBlockedValue, {}}));

    // 가명화 종류의 값은 응답 검사에서 거절하지 않는다(ADR 0017 은 차단 종류만).
    const std::vector<pc::EntitySpan> person{
        *pc::EntitySpan::make(response, pc::SegmentIndex{0}, span, pc::EntityType::Person, pc::DetectorKind::Ner)};
    EXPECT_TRUE(pc::check_response(pc::SensitiveText::copy_of(response), person));
}

TEST(CoreRestore, ResponseCheckFailsClosedOnBadInput) {
    EXPECT_EQ(pc::check_response(pc::SensitiveText(std::string("\xC0\x80")), {}).error().code(),
              ReasonCode::InvalidText);
    const std::string longer(100, 'x');
    const auto far = *pc::ByteSpan::make(pc::Utf8ByteOffset{50}, pc::Utf8ByteOffset{60});
    const std::vector<pc::EntitySpan> outside{
        *pc::EntitySpan::make(longer, pc::SegmentIndex{0}, far, pc::EntityType::KoreanRrn, pc::DetectorKind::Pattern)};
    EXPECT_EQ(pc::check_response(pc::SensitiveText::copy_of("짧음"), outside).error().code(),
              ReasonCode::DetectorUnavailable);
}

TEST(CoreRestore, PlanFromAnotherResponseIsRejected) {
    pa_test::FakeVault vault(3);
    const auto person = *vault.issue(pc::EntityType::Person, "가상인");
    const auto first = checked("앞 " + std::string(person.text()));
    const auto plan = pc::plan_restore(first);
    ASSERT_TRUE(plan);
    const auto restored = pc::apply_restore(checked("다른 " + std::string(person.text()) + " 응답"), *plan, vault);
    ASSERT_FALSE(restored);
    EXPECT_EQ(restored.error().code(), ReasonCode::InternalError);
}
