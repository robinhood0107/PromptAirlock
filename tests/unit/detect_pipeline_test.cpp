// 실제 탐지기를 core 판정에 잇는다: 탐지 → 정책 검사 → 보호 → 보호 후 재탐지 → 잔여 검사 → provider 요청.
// 차단 종류가 있으면 provider 호출이 0 이고, 사용자 거절에는 종류만 있다. 통과하면 원문이 provider 로 가지 않는다.
#include "prompt_airlock/core/grade.hpp"
#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/privacy.hpp"
#include "prompt_airlock/core/provider_boundary.hpp"
#include "prompt_airlock/core/residual.hpp"
#include "prompt_airlock/core/token.hpp"
#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fake_vault.hpp"

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
using pc::EntityType;

namespace {

struct Outcome {
    std::expected<void, pc::Rejection> result;
    int provider_calls = 0;
    std::vector<std::string> sent;
};

Outcome run(std::string_view user_text) {
    Outcome outcome{{}, 0, {}};
    const auto detectors = *pd::Detectors::make({});
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(user_text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts));
    auto raw = pc::RawPrompt::create(*std::move(builder).build(),
                                     *pc::RequestParams::create({}, pc::OutputTokenCap::standard()),
                                     *pc::resolve_grade(pc::GradePolicy::OOnly, {}));

    const auto fail = [&](pc::Rejection r) {
        outcome.result = std::unexpected(std::move(r));
        return std::move(outcome);
    };
    const auto detected = detectors.detect(raw.document());
    if (!detected) {
        return fail(pc::Rejection::from_error(detected.error()));
    }
    auto checked = pc::check_policy(std::move(raw), detected->entities, pc::Policy::standard());
    if (!checked) {
        return fail(checked.error());
    }
    pa_test::FakeVault vault(11);
    auto protected_prompt = pc::protect(std::move(*checked), vault);
    if (!protected_prompt) {
        return fail(protected_prompt.error());
    }
    // 잔여 검사: 보호된 문서를 같은 탐지기로 다시 본다.
    const auto residual = detectors.detect(protected_prompt->document());
    if (!residual) {
        return fail(pc::Rejection::from_error(residual.error()));
    }
    auto verified = pc::verify_residual(std::move(*protected_prompt), pc::ResidualReport{residual->entities, {}});
    if (!verified) {
        return fail(verified.error());
    }
    const auto request = pc::make_provider_request(*verified);
    if (!request) {
        return fail(request.error());
    }
    ++outcome.provider_calls;
    for (const auto& message : request->messages()) {
        for (const auto& part : message.parts) {
            outcome.sent.emplace_back(part.view());
        }
    }
    return outcome;
}

}  // namespace

TEST(DetectPipeline, BlockedTypesNeverReachProvider) {
    const std::vector<std::pair<std::string_view, EntityType>> cases = {
        {"제 주민번호는 900101-1234567 입니다", EntityType::KoreanRrn},
        {"카드 4111-1111-1111-1111 로 결제", EntityType::CardNumber},
        {"키 AKIA0000AAAA1111BBBB 를 넣었어요", EntityType::ApiKey},
        {"여권 M123A4567 사본", EntityType::KoreanPassportNo},
        {"외국인등록번호 ０１０２０３－７１２３４５６", EntityType::KoreanAlienRegistrationNo},
    };
    for (const auto& [text, type] : cases) {
        const auto outcome = run(text);
        ASSERT_FALSE(outcome.result) << pc::entity_type_name(type);
        EXPECT_EQ(outcome.provider_calls, 0);
        const auto user = outcome.result.error().for_user();
        EXPECT_EQ(user.code, pc::ReasonCode::EntityBlocked);
        EXPECT_TRUE(user.blocked_types.contains(type)) << pc::entity_type_name(type);
    }
}

TEST(DetectPipeline, TokenizedValuesLeaveNoOriginalInRequest) {
    const std::string_view text = "010-2345-6789 이나 user1@example.invalid, 192.0.2.10 으로 연락";
    const auto outcome = run(text);
    ASSERT_TRUE(outcome.result);
    ASSERT_EQ(outcome.provider_calls, 1);
    ASSERT_EQ(outcome.sent.size(), 1U);
    for (const std::string_view original : {"010-2345-6789", "2345", "user1@example.invalid", "192.0.2.10"}) {
        EXPECT_EQ(outcome.sent[0].find(original), std::string::npos) << original;
    }
    EXPECT_EQ(pc::scan_tokens(outcome.sent[0]).size(), 3U);
}
