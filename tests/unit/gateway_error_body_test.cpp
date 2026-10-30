#include "prompt_airlock/gateway/error_body.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

namespace {

namespace core = prompt_airlock::core;
namespace gw = prompt_airlock::gateway;
using json = nlohmann::json;

TEST(GatewayErrorBody, EntryErrorsUseCompatibleShape) {
    const auto r = gw::error_response(gw::EntryError::Unauthorized);
    EXPECT_EQ(r.status, 401u);
    const json body = json::parse(r.body);
    ASSERT_TRUE(body.contains("error"));
    EXPECT_EQ(body["error"]["code"], "unauthorized");
    EXPECT_EQ(body["error"]["type"], "authentication_error");
    EXPECT_TRUE(body["error"]["param"].is_null());
    EXPECT_FALSE(body["error"].contains("blocked_types"));
    EXPECT_EQ(gw::error_response(gw::EntryError::BodyTooLarge).status, 413u);
    EXPECT_EQ(gw::error_response(gw::EntryError::TooManyFailures).status, 429u);
    const auto busy = gw::error_response(gw::EntryError::Overloaded);
    EXPECT_EQ(busy.status, 503u);
    EXPECT_EQ(json::parse(busy.body)["error"]["code"], "overloaded");
    const auto late = gw::error_response(gw::EntryError::Timeout);
    EXPECT_EQ(late.status, 504u);
    EXPECT_EQ(json::parse(late.body)["error"]["code"], "timeout");
    EXPECT_EQ(json::parse(gw::error_response(gw::EntryError::Cancelled).body)["error"]["code"], "cancelled");
}

TEST(GatewayErrorBody, RejectionCarriesOnlyCodeAndTypes) {
    core::EntityTypeSet types;
    types.insert(core::EntityType::KoreanRrn);
    const auto r = gw::error_response(core::UserRejection{core::ReasonCode::EntityBlocked, types});
    EXPECT_EQ(r.status, 400u);
    const json body = json::parse(r.body);
    EXPECT_EQ(body["error"]["code"].get<std::string>(), core::reason_code_name(core::ReasonCode::EntityBlocked));
    ASSERT_EQ(body["error"]["blocked_types"].size(), 1u);
    EXPECT_EQ(body["error"]["blocked_types"][0].get<std::string>(), core::entity_type_name(core::EntityType::KoreanRrn));
    // error 객체에는 정해진 다섯 키만 있다
    EXPECT_EQ(body["error"].size(), 5u);
    EXPECT_EQ(body.size(), 1u);
}

TEST(GatewayErrorBody, StatusFollowsReasonRange) {
    const auto status = [](core::ReasonCode code) { return gw::error_response(core::UserRejection{code, {}}).status; };
    EXPECT_EQ(status(core::ReasonCode::GradeSensitive), 403u);
    EXPECT_EQ(status(core::ReasonCode::PromptTooLarge), 413u);
    EXPECT_EQ(status(core::ReasonCode::FieldNotAllowed), 400u);
    EXPECT_EQ(status(core::ReasonCode::ResidualFound), 400u);
    EXPECT_EQ(status(core::ReasonCode::ResponseTokenInLink), 502u);
    EXPECT_EQ(status(core::ReasonCode::DetectorUnavailable), 503u);
    EXPECT_EQ(status(core::ReasonCode::InternalError), 500u);
}

}  // namespace
