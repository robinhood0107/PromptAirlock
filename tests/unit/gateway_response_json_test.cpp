#include "prompt_airlock/gateway/response_json.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <string>

#include "../../src/gateway/role_name.hpp"

namespace {

namespace core = prompt_airlock::core;
namespace gw = prompt_airlock::gateway;
using json = nlohmann::json;

std::string model_role() { return std::string(gw::detail::role_name(core::MessageRole::Model)); }

json answer(json message_extra = json::object(), json choice_extra = json::object()) {
    json message = {{"role", model_role()}, {"content", "답입니다"}, {"refusal", nullptr}, {"annotations", json::array()}};
    message.update(message_extra);
    json choice = {{"index", 0}, {"message", message}, {"finish_reason", "stop"}, {"logprobs", nullptr}};
    choice.update(choice_extra);
    return {{"id", "provider-id"}, {"object", "chat.completion"}, {"created", 1}, {"model", "provider-model"},
            {"system_fingerprint", "fp"}, {"choices", json::array({choice})},
            {"usage", {{"prompt_tokens", 3}, {"completion_tokens", 4}, {"total_tokens", 7}, {"details", {{"x", 1}}}}}};
}

TEST(GatewayResponseJson, ReadsOnlyAllowedFields) {
    const auto parsed = gw::parse_provider_answer(answer().dump());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->content.view(), "답입니다");
    EXPECT_EQ(parsed->finish_reason, "stop");
    ASSERT_TRUE(parsed->usage.has_value());
    EXPECT_EQ(parsed->usage->total_tokens, 7);
}

TEST(GatewayResponseJson, RejectsToolsAudioAndLogprobs) {
    const json call = json::array({{{"id", "c"}, {"type", "function"}}});
    EXPECT_EQ(gw::parse_provider_answer(answer({{"tool_calls", call}}).dump()).error(), gw::AnswerError::Forbidden);
    EXPECT_EQ(gw::parse_provider_answer(answer({{"tool_calls", json::array()}}).dump()).error(), gw::AnswerError::Forbidden);
    EXPECT_EQ(gw::parse_provider_answer(answer({{"audio", {{"data", "x"}}}}).dump()).error(), gw::AnswerError::Forbidden);
    EXPECT_EQ(gw::parse_provider_answer(answer(json::object(), {{"logprobs", {{"content", json::array()}}}}).dump()).error(),
              gw::AnswerError::Forbidden);
    // null 은 없는 것과 같다
    EXPECT_TRUE(gw::parse_provider_answer(answer({{"tool_calls", nullptr}}).dump()).has_value());
}

TEST(GatewayResponseJson, RejectsMalformedAnswers) {
    EXPECT_EQ(gw::parse_provider_answer("").error(), gw::AnswerError::Malformed);
    EXPECT_EQ(gw::parse_provider_answer("[]").error(), gw::AnswerError::Malformed);
    EXPECT_EQ(gw::parse_provider_answer(answer({{"content", nullptr}}).dump()).error(), gw::AnswerError::Malformed);
    EXPECT_EQ(gw::parse_provider_answer(answer({{"role", "user"}}).dump()).error(), gw::AnswerError::Malformed);
    std::string duplicate = answer().dump();
    duplicate.insert(1, R"("id":"again",)");
    EXPECT_EQ(gw::parse_provider_answer(duplicate).error(), gw::AnswerError::Malformed);
    std::string deep = answer().dump();
    deep.insert(deep.size() - 1, R"(,"extra":)" + std::string(20, '[') + std::string(20, ']'));
    EXPECT_EQ(gw::parse_provider_answer(deep).error(), gw::AnswerError::Malformed);
}

TEST(GatewayResponseJson, ClientResponseIsRebuilt) {
    const json body = json::parse(gw::client_response_body("chatcmpl-pa-1", 42, "demo-alias", "복원된 답", "length",
                                                           gw::Usage{1, 2, 3}));
    EXPECT_EQ(body["id"], "chatcmpl-pa-1");
    EXPECT_EQ(body["model"], "demo-alias");
    EXPECT_EQ(body["choices"][0]["message"]["content"], "복원된 답");
    EXPECT_EQ(body["choices"][0]["message"]["role"].get<std::string>(), model_role());
    EXPECT_EQ(body["choices"][0]["finish_reason"], "length");
    EXPECT_EQ(body["usage"]["total_tokens"], 3);
    EXPECT_FALSE(body.contains("system_fingerprint"));
}

TEST(GatewayResponseJson, OddFinishReasonBecomesStop) {
    const auto parsed = gw::parse_provider_answer(answer(json::object(), {{"finish_reason", "<script>"}}).dump());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->finish_reason, "stop");
}

}  // namespace
