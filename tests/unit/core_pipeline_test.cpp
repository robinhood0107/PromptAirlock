// 처음부터 끝까지: 등급 확정 → 정책 검사 → 보호 → 잔여 검사 → provider 요청 → 응답 검사 → 복원.
// 거절 경로에서는 provider 요청이 만들어지지 않고(mock provider 호출 0), 만들어진 요청에는 원문이 없다.
#include "prompt_airlock/core/grade.hpp"
#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/privacy.hpp"
#include "prompt_airlock/core/provider_boundary.hpp"
#include "prompt_airlock/core/residual.hpp"
#include "prompt_airlock/core/restore.hpp"

#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fake_vault.hpp"

namespace pc = prompt_airlock::core;
using pc::EntityType;
using pc::ReasonCode;

namespace {

// 합성 대화. 위치는 각 segment 텍스트 기준 byte 다.
const std::string system_text = "가상기관 업무 도우미입니다.";
const std::string user_text = "가상인 과장에게 user1@example.invalid 로 회신해 주세요.";
const std::string stop_text = "가상인";
constexpr std::size_t user_segment = 1, stop_segment = 2;

pc::EntitySpan entity(std::uint32_t segment, std::string_view text, std::string_view value, EntityType type) {
    const auto begin = text.find(value);
    const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{begin + value.size()});
    return *pc::EntitySpan::make(text, pc::SegmentIndex{segment}, span, type, pc::DetectorKind::Pattern);
}

std::vector<pc::EntitySpan> clean_detections() {
    return {entity(user_segment, user_text, "가상인", EntityType::Person),
            entity(user_segment, user_text, "user1@example.invalid", EntityType::Email),
            entity(stop_segment, stop_text, "가상인", EntityType::Person)};
}

struct MockProvider {
    int calls = 0;
    std::vector<std::string> received;
    void send(const pc::ProviderRequest& request) {
        ++calls;
        for (const auto& message : request.messages()) {
            for (const auto& part : message.parts) {
                received.emplace_back(part.view());
            }
        }
        for (const auto& stop : request.stop()) {
            received.emplace_back(stop.view());
        }
    }
};

struct Scenario {
    std::vector<std::string_view> grade_marks;
    std::vector<pc::EntitySpan> detected = clean_detections();
    // 보호 후 텍스트를 받아 잔여 검사 결과를 만든다(실제로는 Phase 5 detector 가 다시 돈다).
    std::function<pc::ResidualReport(const pc::ProtectedPrompt&)> residual = [](const pc::ProtectedPrompt&) {
        return pc::ResidualReport{};
    };
};

// Gateway 의 요청 처리 순서를 그대로 흉내 낸다. 거절이면 provider 를 부르지 않는다.
std::expected<void, pc::Rejection> run(const Scenario& scenario, pa_test::FakeVault& vault, MockProvider& provider) {
    const auto grade = pc::resolve_grade(pc::GradePolicy::Declare, scenario.grade_marks);
    if (!grade) {
        return std::unexpected(grade.error());
    }
    std::vector<pc::SensitiveText> system_parts;
    system_parts.push_back(pc::SensitiveText::copy_of(system_text));
    std::vector<pc::SensitiveText> user_parts;
    user_parts.push_back(pc::SensitiveText::copy_of(user_text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::System, pc::ContentForm::String, std::move(system_parts))
        .add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(user_parts))
        .add_stop(pc::SensitiveText::copy_of(stop_text));
    auto raw = pc::RawPrompt::create(*std::move(builder).build(),
                                     *pc::RequestParams::create({.max_tokens = 500}, pc::OutputTokenCap::standard()),
                                     *grade);

    auto checked = pc::check_policy(std::move(raw), scenario.detected, pc::Policy::standard());
    if (!checked) {
        return std::unexpected(checked.error());
    }
    auto protected_prompt = pc::protect(std::move(*checked), vault);
    if (!protected_prompt) {
        return std::unexpected(protected_prompt.error());
    }
    const auto report = scenario.residual(*protected_prompt);
    auto verified = pc::verify_residual(std::move(*protected_prompt), report);
    if (!verified) {
        return std::unexpected(verified.error());
    }
    auto request = pc::make_provider_request(*verified);
    if (!request) {
        return std::unexpected(request.error());
    }
    provider.send(*request);
    return {};
}

ReasonCode rejected(const Scenario& scenario) {
    pa_test::FakeVault vault(7);
    MockProvider provider;
    const auto result = run(scenario, vault, provider);
    EXPECT_FALSE(result);
    EXPECT_EQ(provider.calls, 0);
    return result ? ReasonCode::InternalError : result.error().code();
}

}  // namespace

TEST(CorePipeline, CleanRequestReachesProviderWithoutOriginals) {
    pa_test::FakeVault vault(7);
    MockProvider provider;
    ASSERT_TRUE(run(Scenario{.grade_marks = {"O"}}, vault, provider));
    ASSERT_EQ(provider.calls, 1);
    ASSERT_EQ(provider.received.size(), 3U);  // system, user, stop
    EXPECT_EQ(provider.received[0], system_text);  // 탐지 대상이 없는 segment 는 그대로
    for (const auto& sent : provider.received) {
        EXPECT_EQ(sent.find("가상인"), std::string::npos) << sent;
        EXPECT_EQ(sent.find("user1@example.invalid"), std::string::npos) << sent;
    }
    // 같은 이름은 메시지와 stop 에서 같은 token 이다.
    EXPECT_EQ(pc::scan_tokens(provider.received[1])[0].token, pc::scan_tokens(provider.received[2])[0].token);
    EXPECT_EQ(vault.issued(), 2U);
}

TEST(CorePipeline, ProviderRequestKeepsShapeAndParameters) {
    pa_test::FakeVault vault(7);
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of("첫 part"));
    parts.push_back(pc::SensitiveText::copy_of("둘째 part"));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::Developer, pc::ContentForm::TextParts, std::move(parts));
    auto raw = pc::RawPrompt::create(*std::move(builder).build(),
                                     *pc::RequestParams::create({.max_completion_tokens = 9000, .temperature = 0.2},
                                                                pc::OutputTokenCap::standard()),
                                     *pc::resolve_grade(pc::GradePolicy::OOnly, {}));
    auto verified = pc::verify_residual(*pc::protect(*pc::check_policy(std::move(raw), {}, pc::Policy::standard()), vault),
                                        {});
    ASSERT_TRUE(verified);
    const auto request = pc::make_provider_request(*verified);
    ASSERT_TRUE(request);
    ASSERT_EQ(request->messages().size(), 1U);
    EXPECT_EQ(request->messages()[0].role, pc::MessageRole::Developer);
    EXPECT_EQ(request->messages()[0].form, pc::ContentForm::TextParts);
    EXPECT_EQ(request->messages()[0].parts[1].view(), "둘째 part");
    EXPECT_TRUE(request->stop().empty());
    EXPECT_EQ(request->params().max_output_tokens(), 4096U);
    EXPECT_EQ(request->params().temperature(), 0.2);

    // 넘겨져 빈 검증 완료 질문으로는 요청을 만들지 않는다.
    const auto taken = std::move(*verified);
    EXPECT_EQ(pc::make_provider_request(*verified).error().code(), ReasonCode::InternalError);
    EXPECT_TRUE(pc::make_provider_request(taken));
}

TEST(CorePipeline, GradeRejectionsNeverReachProvider) {
    EXPECT_EQ(rejected(Scenario{.grade_marks = {"S"}}), ReasonCode::GradeSensitive);
    EXPECT_EQ(rejected(Scenario{.grade_marks = {"C"}}), ReasonCode::GradeClassified);
    EXPECT_EQ(rejected(Scenario{.grade_marks = {}}), ReasonCode::GradeUnresolved);
}

TEST(CorePipeline, BlockedEntityNeverReachesProvider) {
    auto detected = clean_detections();
    detected.push_back(entity(user_segment, user_text, "회신", EntityType::KoreanRrn));
    EXPECT_EQ(rejected(Scenario{.grade_marks = {"O"}, .detected = detected}), ReasonCode::EntityBlocked);
}

TEST(CorePipeline, ResidualValueNeverReachesProvider) {
    Scenario scenario{.grade_marks = {"O"}};
    // 보호 뒤에도 탐지기가 이메일 조각("example.invalid")을 찾았다고 가정한다.
    scenario.detected = {entity(user_segment, user_text, "가상인", EntityType::Person)};
    scenario.residual = [](const pc::ProtectedPrompt& prompt) {
        const auto text = prompt.document().segments()[user_segment].text();
        return pc::ResidualReport{{entity(user_segment, text, "user1@example.invalid", EntityType::Email)}, {}};
    };
    EXPECT_EQ(rejected(scenario), ReasonCode::ResidualFound);
}

TEST(CorePipeline, DetectionsInsideTokensAreIgnored) {
    Scenario scenario{.grade_marks = {"O"}};
    // 탐지기가 token 안의 글자를 무언가로 오인해도 생성한 token 이라 원문이 없다.
    scenario.residual = [](const pc::ProtectedPrompt& prompt) {
        const auto& replacement = prompt.replacements()[0];
        const auto text = prompt.document().segments()[replacement.segment.value()].text();
        const auto inner = *pc::ByteSpan::make(pc::Utf8ByteOffset{replacement.span.begin().value() + 3},
                                               pc::Utf8ByteOffset{replacement.span.begin().value() + 9});
        return pc::ResidualReport{
            {*pc::EntitySpan::make(text, replacement.segment, inner, EntityType::ApiKey, pc::DetectorKind::Secret)},
            {}};
    };
    pa_test::FakeVault vault(7);
    MockProvider provider;
    EXPECT_TRUE(run(scenario, vault, provider));
    EXPECT_EQ(provider.calls, 1);
}

TEST(CorePipeline, EncodedTargetNeverReachesProvider) {
    Scenario scenario{.grade_marks = {"O"}};
    scenario.residual = [](const pc::ProtectedPrompt&) {
        pc::EntityTypeSet rrn;
        rrn.insert(EntityType::KoreanRrn);
        return pc::ResidualReport{{},
                                  {pc::EncodedFinding{pc::SegmentIndex{0},
                                                      *pc::ByteSpan::make(pc::Utf8ByteOffset{0}, pc::Utf8ByteOffset{3}),
                                                      pc::EncodingKind::Base64, *pc::DecodeDepth::make(1), true, false,
                                                      rrn}}};
    };
    EXPECT_EQ(rejected(scenario), ReasonCode::EncodedTarget);
}

TEST(CorePipeline, InvalidResidualSpanFailsClosed) {
    Scenario scenario{.grade_marks = {"O"}};
    scenario.residual = [](const pc::ProtectedPrompt&) {
        const std::string longer(500, 'x');
        const auto far = *pc::ByteSpan::make(pc::Utf8ByteOffset{400}, pc::Utf8ByteOffset{410});
        return pc::ResidualReport{
            {*pc::EntitySpan::make(longer, pc::SegmentIndex{0}, far, EntityType::Person, pc::DetectorKind::Ner)}, {}};
    };
    EXPECT_EQ(rejected(scenario), ReasonCode::DetectorUnavailable);
}

TEST(CorePipeline, ResponseRoundTripRestoresOriginals) {
    pa_test::FakeVault vault(7);
    MockProvider provider;
    ASSERT_TRUE(run(Scenario{.grade_marks = {"O"}}, vault, provider));
    // mock provider 는 받은 질문(token 상태)을 그대로 인용해 답한다.
    const std::string answer = "확인했습니다. " + provider.received[1];
    auto checked = pc::check_response(pc::SensitiveText::copy_of(answer), {});
    ASSERT_TRUE(checked);
    const auto plan = pc::plan_restore(*checked);
    ASSERT_TRUE(plan);
    EXPECT_EQ(plan->occurrences.size(), 2U);
    const auto restored = pc::apply_restore(std::move(*checked), *plan, vault);
    ASSERT_TRUE(restored);
    EXPECT_EQ(restored->view(), "확인했습니다. " + user_text);
}
