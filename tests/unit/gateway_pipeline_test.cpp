// 처리 단계 시험: 가짜 가명 범위와 가짜 provider 로, 거절 경로마다 provider 호출이 0 인지와
// provider 로 나가는 본문에 원문이 없는지를 본다.
#include "prompt_airlock/gateway/pipeline.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "../../src/gateway/role_name.hpp"
#include "fake_vault.hpp"
#include "mock_provider.hpp"

namespace {

namespace asio = boost::asio;
namespace core = prompt_airlock::core;
namespace detect = prompt_airlock::detect;
namespace gw = prompt_airlock::gateway;
using json = nlohmann::json;

// 가짜 범위가 실패하도록 고를 수 있게 감싼다.
class TestScope {
public:
    TestScope(std::shared_ptr<pa_test::FakeVault> vault, bool fail_issue) : vault_(std::move(vault)), fail_(fail_issue) {}
    std::expected<core::Token, core::ProtectionError> issue(core::EntityType type, std::string_view value) {
        if (fail_) {
            return std::unexpected(core::ProtectionError::IssuerUnavailable);
        }
        return vault_->issue(type, value);
    }
    std::expected<core::SensitiveText, core::RestoreError> resolve(const core::Token& token) {
        return vault_->resolve(token);
    }

private:
    std::shared_ptr<pa_test::FakeVault> vault_;
    bool fail_;
};

class FailingNer final : public detect::NerScanner {
public:
    std::expected<std::vector<core::EntitySpan>, core::DetectError> scan(std::string_view, core::SegmentIndex,
                                                                        const detect::DetectionView&) const override {
        return std::unexpected(core::DetectError::Unavailable);
    }
};

class GatewayPipeline : public ::testing::Test {
protected:
    gw::Pipeline make(const detect::Detectors& detectors) {
        return gw::Pipeline(
            detectors,
            [this]() -> std::expected<gw::PseudonymScope, core::VaultError> {
                if (vault_down_) {
                    return std::unexpected(core::VaultError::Unavailable);
                }
                return gw::PseudonymScope(TestScope(vault_, issuer_fails_));
            },
            [this](std::string body) -> asio::awaitable<std::expected<gw::ProviderReply, gw::ProviderError>> {
                ++provider_calls_;
                sent_.push_back(std::move(body));
                if (provider_fails_) {
                    co_return std::unexpected(gw::ProviderError::Timeout);
                }
                co_return gw::ProviderReply{200, answer_ ? answer_(sent_.back()) : pa_mock::make_answer(sent_.back())};
            },
            *core::OutputTokenCap::make(512), "demo-alias");
    }

    gw::JsonResponse run(const gw::Pipeline& pipeline, std::string body,
                         core::GradePolicy policy = core::GradePolicy::OOnly) {
        asio::io_context io;
        auto grade = core::resolve_grade(policy, {});
        auto future = asio::co_spawn(io, pipeline.handle(gw::AcceptedRequest{nullptr, *grade, std::move(body)}),
                                     asio::use_future);
        io.run();
        return future.get();
    }

    static std::string ask(std::string_view text) {
        return json{{"model", "client-model"}, {"messages", json::array({{{"role", "user"}, {"content", text}}})}}.dump();
    }

    static std::string code_of(const gw::JsonResponse& r) { return json::parse(r.body)["error"]["code"]; }

    // provider 가 내는 답(content 만 정한다)
    static std::string answer_with(std::string_view content, json message_extra = json::object()) {
        json message = {{"role", gw::detail::role_name(core::MessageRole::Model)}, {"content", content}};
        message.update(message_extra);
        return json{{"choices", json::array({{{"index", 0}, {"message", message}, {"finish_reason", "stop"}}})}}.dump();
    }

    // 보낸 본문에서 첫 token 을 꺼낸다
    static std::string first_token(const std::string& sent) {
        const auto open = sent.find(core::token_open);
        const auto close = sent.find(core::token_close, open);
        return sent.substr(open, close + core::token_close.size() - open);
    }

    std::function<std::string(const std::string&)> answer_;

    detect::Detectors detectors_ = *detect::Detectors::make({});
    std::shared_ptr<pa_test::FakeVault> vault_ = std::make_shared<pa_test::FakeVault>(20261022);
    bool vault_down_ = false;
    bool issuer_fails_ = false;
    bool provider_fails_ = false;
    int provider_calls_ = 0;
    std::vector<std::string> sent_;
};

TEST_F(GatewayPipeline, SendsOnlyPseudonymizedRequestBuiltByGateway) {
    const auto pipeline = make(detectors_);
    const auto reply = run(pipeline, ask("담당자 연락처 010-2345-6789, 메일 kim.demo@example.org 로 회신 부탁"));
    ASSERT_EQ(provider_calls_, 1);
    const json sent = json::parse(sent_.front());
    // 원문은 나가지 않는다
    EXPECT_EQ(sent_.front().find("010-2345-6789"), std::string::npos);
    EXPECT_EQ(sent_.front().find("kim.demo@example.org"), std::string::npos);
    const std::string content = sent["messages"][0]["content"];
    EXPECT_NE(content.find(std::string(core::token_open)), std::string::npos);
    // 게이트웨이가 정한 값만 들어간다
    EXPECT_EQ(sent["model"], "demo-alias");
    EXPECT_EQ(sent["max_tokens"], 512);
    EXPECT_EQ(sent["n"], 1);
    EXPECT_EQ(sent["stream"], false);
    EXPECT_FALSE(sent.contains("store"));
    // 답은 같은 범위에서 원래 값으로 되돌아온다
    ASSERT_EQ(reply.status, 200u) << reply.body;
    const json answer = json::parse(reply.body);
    const std::string restored = answer["choices"][0]["message"]["content"];
    EXPECT_NE(restored.find("010-2345-6789"), std::string::npos);
    EXPECT_NE(restored.find("kim.demo@example.org"), std::string::npos);
    EXPECT_EQ(restored.find(std::string(core::token_open)), std::string::npos);
    EXPECT_EQ(answer["model"], "demo-alias");
    EXPECT_TRUE(answer["id"].get<std::string>().starts_with("chatcmpl-pa-"));
}

TEST_F(GatewayPipeline, KeepsContentPartsAndStop) {
    const auto pipeline = make(detectors_);
    const std::string body =
        R"({"messages":[{"role":"user","content":[{"type":"text","text":"첫째"},{"type":"text","text":"둘째"}]}],)"
        R"("stop":"끝","max_tokens":100000,"temperature":0.2})";
    (void)run(pipeline, body);
    ASSERT_EQ(provider_calls_, 1);
    const json sent = json::parse(sent_.front());
    ASSERT_TRUE(sent["messages"][0]["content"].is_array());
    EXPECT_EQ(sent["messages"][0]["content"][1]["text"], "둘째");
    EXPECT_EQ(sent["stop"][0], "끝");
    EXPECT_EQ(sent["max_tokens"], 512);  // 상한으로 줄인다
    EXPECT_EQ(sent["temperature"], 0.2);
}

TEST_F(GatewayPipeline, EveryRejectionMakesZeroProviderCalls) {
    const auto pipeline = make(detectors_);
    struct Case {
        std::string body;
        core::ReasonCode code;
    };
    const std::vector<Case> cases = {
        {"{", core::ReasonCode::InvalidText},
        {R"({"messages":[{"role":"user","content":"a"}],"stream":true})", core::ReasonCode::StreamNotAllowed},
        {R"({"messages":[{"role":"user","content":"a"}],"n":2})", core::ReasonCode::ParameterOutOfRange},
        {ask("제 주민번호는 900101-1234567 입니다"), core::ReasonCode::EntityBlocked},
        // 합성 주민번호를 base64 로 감싼 것
        {ask("확인 부탁: OTAwMTAxLTEyMzQ1Njc="), core::ReasonCode::EncodedTarget},
    };
    for (const auto& c : cases) {
        const auto reply = run(pipeline, c.body);
        EXPECT_EQ(code_of(reply), core::reason_code_name(c.code)) << c.body;
    }
    EXPECT_EQ(provider_calls_, 0);
}

TEST_F(GatewayPipeline, BlockedTypesAreReportedWithoutValues) {
    const auto pipeline = make(detectors_);
    const auto reply = run(pipeline, ask("제 주민번호는 900101-1234567 입니다"));
    EXPECT_EQ(reply.status, 400u);
    EXPECT_EQ(reply.body.find("900101"), std::string::npos);
    EXPECT_EQ(json::parse(reply.body)["error"]["blocked_types"][0].get<std::string>(), core::entity_type_name(core::EntityType::KoreanRrn));
}

TEST_F(GatewayPipeline, InfrastructureFailuresFailClosed) {
    const auto pipeline = make(detectors_);
    vault_down_ = true;
    EXPECT_EQ(run(pipeline, ask("연락처 010-2345-6789")).status, 503u);
    vault_down_ = false;
    issuer_fails_ = true;
    EXPECT_EQ(run(pipeline, ask("연락처 010-2345-6789")).status, 503u);
    issuer_fails_ = false;
    const auto broken = detect::Detectors::make({}, std::make_shared<FailingNer>());
    ASSERT_TRUE(broken.has_value());
    const auto ner_down = make(*broken);
    EXPECT_EQ(code_of(run(ner_down, ask("회의 안건 정리"))), core::reason_code_name(core::ReasonCode::DetectorUnavailable));
    EXPECT_EQ(provider_calls_, 0);
}

TEST_F(GatewayPipeline, ProviderFailureReturnsFixedError) {
    provider_fails_ = true;
    const auto pipeline = make(detectors_);
    const auto reply = run(pipeline, ask("회의 안건 정리"));
    EXPECT_EQ(reply.status, 502u);
    EXPECT_EQ(code_of(reply), "provider_error");
}

TEST_F(GatewayPipeline, ResponseChecksRejectUnsafeAnswers) {
    const auto pipeline = make(detectors_);
    const auto code = [&](std::function<std::string(const std::string&)> answer) {
        answer_ = std::move(answer);
        return code_of(run(pipeline, ask("연락처 010-2345-6789 로 안내")));
    };
    // 링크 주소 안의 token
    EXPECT_EQ(code([](const std::string& sent) { return answer_with("[자료](https://example.org/?q=" + first_token(sent) + ")"); }),
              core::reason_code_name(core::ReasonCode::ResponseTokenInLink));
    // 모델이 바꾼 token: 되돌리지 않고 응답 전체를 거절한다
    EXPECT_EQ(code([](const std::string& sent) {
                  std::string token = first_token(sent);
                  const auto last = token.size() - core::token_close.size() - 1;
                  token[last] = token[last] == 'A' ? 'B' : 'A';  // 같은 문자 집합 안에서 한 글자만 바꾼다
                  return answer_with("연락처는 " + token + " 입니다");
              }),
              core::reason_code_name(core::ReasonCode::ResponseTokenUnresolved));
    // 차단 종류 값이 답에 새로 나타남
    EXPECT_EQ(code([](const std::string&) { return answer_with("예시 번호 900101-1234567"); }),
              core::reason_code_name(core::ReasonCode::ResponseBlockedValue));
    // 스크립트가 담긴 답(대소문자 섞어도)
    EXPECT_EQ(code([](const std::string&) { return answer_with("<ScRiPt>alert(1)</script>"); }),
              core::reason_code_name(core::ReasonCode::ResponseActiveContent));
    EXPECT_EQ(code([](const std::string&) { return answer_with("[x](JavaScript:alert(1))"); }),
              core::reason_code_name(core::ReasonCode::ResponseActiveContent));
    // 도구 호출이 담긴 답
    EXPECT_EQ(code([](const std::string&) { return answer_with("x", {{"tool_calls", json::array({{{"id", "c"}}})}}); }),
              "provider_error");
}

}  // namespace
