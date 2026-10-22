#include "prompt_airlock/gateway/request_json.hpp"

#include <gtest/gtest.h>

#include <string>
#include <variant>

#include "../../src/gateway/role_name.hpp"

namespace {

namespace core = prompt_airlock::core;
namespace gw = prompt_airlock::gateway;
using core::ReasonCode;

std::string model_role() { return std::string(gw::detail::role_name(core::MessageRole::Model)); }

ReasonCode code_of(std::string_view body) {
    const auto parsed = gw::parse_request(body);
    EXPECT_FALSE(parsed.has_value()) << body;
    return parsed ? ReasonCode::InternalError : parsed.error().code();
}

TEST(GatewayRequestJson, ReadsAllowedFields) {
    const std::string body = R"({"model":"x","messages":[{"role":"system","content":"규칙"},)"
                             R"({"role":"user","content":[{"type":"text","text":"첫째"},{"type":"text","text":"둘째"}]},)"
                             R"({"role":")" + model_role() + R"(","content":"앞 답"}],)"
                             R"("max_tokens":100,"temperature":0.5,"top_p":1,"stop":["끝","그만"],"n":1,)"
                             R"("stream":false,"response_format":{"type":"json_object"},"max_completion_tokens":null})";
    const auto parsed = gw::parse_request(body);
    ASSERT_TRUE(parsed.has_value()) << static_cast<int>(parsed.error().code());
    EXPECT_EQ(parsed->document.message_count(), 3u);
    // 메시지 part 4개 + stop 2개
    ASSERT_EQ(parsed->document.segments().size(), 6u);
    EXPECT_EQ(parsed->document.segments()[2].text(), "둘째");
    EXPECT_EQ(parsed->document.content_form(1), core::ContentForm::TextParts);
    const auto source = std::get<core::MessageSource>(parsed->document.segments()[3].source());  // source() 는 값을 돌려준다
    EXPECT_EQ(source.role, core::MessageRole::Model);
    EXPECT_EQ(parsed->params.max_tokens, 100);
    EXPECT_FALSE(parsed->params.max_completion_tokens.has_value());
    EXPECT_EQ(parsed->params.temperature, 0.5);
    EXPECT_EQ(parsed->params.top_p, 1.0);
    EXPECT_EQ(parsed->params.n, 1);
    EXPECT_EQ(parsed->params.stream, false);
    EXPECT_EQ(parsed->params.response_format, core::ResponseFormat::JsonObject);
}

TEST(GatewayRequestJson, StopMayBeSingleString) {
    const auto parsed = gw::parse_request(R"({"messages":[{"role":"user","content":"a"}],"stop":"끝"})");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->document.segments().size(), 2u);
}

TEST(GatewayRequestJson, RejectsBrokenJsonAsInvalidText) {
    for (const std::string_view body : {"", "{", "[]", "\"x\"", "1", "{\"messages\":[]} trailing",
                                        "{\"messages\":[{\"role\":\"user\",\"content\":\"\xff\"}]}",
                                        "{\"temperature\":1e400,\"messages\":[]}", "{/*c*/\"messages\":[]}"}) {
        EXPECT_EQ(code_of(body), ReasonCode::InvalidText) << body;
    }
}

TEST(GatewayRequestJson, RejectsUnknownAndDuplicateKeys) {
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":"a"}],"store":true})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":"a"}],"tools":[]})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":"a","name":"kim"}]})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":"a","tool_calls":[]}]})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"tool","content":"a"}]})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":"a"}],"messages":[]})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","role":"system","content":"a"}]})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"content":"a"}]})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user"}]})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":null}]})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":["hi"]})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":null})"), ReasonCode::FieldNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":"a"}],"stop":[["x"]]})"), ReasonCode::FieldNotAllowed);
}

TEST(GatewayRequestJson, RejectsNonTextParts) {
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"x"}}]}]})"),
              ReasonCode::ContentPartNotAllowed);
    // 키 순서가 바뀌어도 같다
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":[{"image_url":{"url":"x"},"type":"image_url"}]}]})"),
              ReasonCode::ContentPartNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":[{"text":"a"}]}]})"), ReasonCode::ContentPartNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":[{"type":"text"}]}]})"), ReasonCode::ContentPartNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":["a"]}]})"), ReasonCode::ContentPartNotAllowed);
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":[{"type":"text","text":1}]}]})"),
              ReasonCode::ContentPartNotAllowed);
}

TEST(GatewayRequestJson, RejectsBadParameterShapes) {
    const std::string head = R"({"messages":[{"role":"user","content":"a"}],)";
    for (const std::string_view tail : {R"("max_tokens":1.5})", R"("max_tokens":"10"})", R"("n":true})",
                                        R"("temperature":"hot"})", R"("stream":1})", R"("max_tokens":18446744073709551615})",
                                        R"("response_format":{"type":"json_schema"}})", R"("response_format":{}})",
                                        R"("response_format":{"type":"text","json_schema":{}}})", R"("top_p":[1]})"}) {
        EXPECT_EQ(code_of(head + std::string(tail)), ReasonCode::ParameterOutOfRange) << tail;
    }
}

TEST(GatewayRequestJson, LimitsNestingDepth) {
    // 허용 모양의 깊이는 5 를 넘지 않는다. 더 깊은 입력은 모양 검사나 깊이 상한에서 멈춘다(스택을 쌓지 않는다)
    std::string deep = R"({"messages":[{"role":"user","content":"a"}],"stop":)";
    deep += std::string(20, '[') + std::string(20, ']') + "}";
    EXPECT_NE(code_of(deep), ReasonCode::InternalError);
    std::string very_deep = std::string(100000, '[') + std::string(100000, ']');
    EXPECT_EQ(code_of(very_deep), ReasonCode::InvalidText);
    std::string objects;
    for (int i = 0; i < 20; ++i) {
        objects += R"({"response_format":)";
    }
    EXPECT_NE(code_of(objects), ReasonCode::InternalError);
}

TEST(GatewayRequestJson, DocumentRulesComeFromCore) {
    EXPECT_EQ(code_of(R"({"messages":[]})"), core::to_reason(core::InputError::EmptyDocument));
    EXPECT_EQ(code_of(R"({"messages":[{"role":"user","content":[]}]})"), core::to_reason(core::InputError::EmptyContent));
    const std::string big = R"({"messages":[{"role":"user","content":")" + std::string(70 * 1024, 'a') + R"("}]})";
    EXPECT_EQ(code_of(big), ReasonCode::PromptTooLarge);
}

}  // namespace
