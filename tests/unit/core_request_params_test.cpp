#include "prompt_airlock/core/request_params.hpp"

#include <gtest/gtest.h>

#include <limits>
#include <type_traits>

namespace pc = prompt_airlock::core;
using pc::ReasonCode;

// 범위 검사 없이 만들 수 없다.
static_assert(!std::is_default_constructible_v<pc::RequestParams>);
static_assert(!std::is_constructible_v<pc::RequestParams, std::uint32_t, std::optional<double>, std::optional<double>,
                                       std::optional<pc::ResponseFormat>>);
static_assert(!std::is_constructible_v<pc::OutputTokenCap, std::uint32_t>);

namespace {

ReasonCode reject(const pc::RequestParamsInput& input) {
    const auto made = pc::RequestParams::create(input, pc::OutputTokenCap::standard());
    return made ? ReasonCode::InternalError : made.error().code();
}

}  // namespace

TEST(CoreRequestParams, OutputTokenCapRange) {
    EXPECT_EQ(pc::OutputTokenCap::standard().value(), 4096U);
    EXPECT_FALSE(pc::OutputTokenCap::make(0));
    EXPECT_EQ(pc::OutputTokenCap::make(1)->value(), 1U);
    EXPECT_EQ(pc::OutputTokenCap::make(65536)->value(), 65536U);
    EXPECT_FALSE(pc::OutputTokenCap::make(65537));
}

TEST(CoreRequestParams, MaxTokensDefaultsAndClamps) {
    const auto cap = pc::OutputTokenCap::standard();
    EXPECT_EQ(pc::RequestParams::create({}, cap)->max_output_tokens(), 4096U);
    EXPECT_EQ(pc::RequestParams::create({.max_tokens = 100}, cap)->max_output_tokens(), 100U);
    EXPECT_EQ(pc::RequestParams::create({.max_completion_tokens = 1'000'000}, cap)->max_output_tokens(), 4096U);
    EXPECT_EQ(pc::RequestParams::create({.max_tokens = 300, .max_completion_tokens = 300}, cap)->max_output_tokens(),
              300U);
    EXPECT_EQ(pc::RequestParams::create({.max_tokens = 9000}, *pc::OutputTokenCap::make(8192))->max_output_tokens(),
              8192U);
}

TEST(CoreRequestParams, RejectsBadMaxTokens) {
    EXPECT_EQ(reject({.max_tokens = 0}), ReasonCode::ParameterOutOfRange);
    EXPECT_EQ(reject({.max_completion_tokens = -5}), ReasonCode::ParameterOutOfRange);
    EXPECT_EQ(reject({.max_tokens = 100, .max_completion_tokens = 200}), ReasonCode::ParameterOutOfRange);
}

TEST(CoreRequestParams, SamplingRanges) {
    const auto nan = std::numeric_limits<double>::quiet_NaN();
    const auto inf = std::numeric_limits<double>::infinity();
    EXPECT_TRUE(pc::RequestParams::create({.temperature = 0.0, .top_p = 1.0}, pc::OutputTokenCap::standard()));
    EXPECT_TRUE(pc::RequestParams::create({.temperature = 2.0, .top_p = 0.0}, pc::OutputTokenCap::standard()));
    EXPECT_EQ(reject({.temperature = 2.01}), ReasonCode::ParameterOutOfRange);
    EXPECT_EQ(reject({.temperature = -0.1}), ReasonCode::ParameterOutOfRange);
    EXPECT_EQ(reject({.temperature = nan}), ReasonCode::ParameterOutOfRange);
    EXPECT_EQ(reject({.top_p = inf}), ReasonCode::ParameterOutOfRange);
    EXPECT_EQ(reject({.top_p = 1.5}), ReasonCode::ParameterOutOfRange);
}

TEST(CoreRequestParams, OnlySingleNonStreamingCompletion) {
    EXPECT_TRUE(pc::RequestParams::create({.n = 1, .stream = false}, pc::OutputTokenCap::standard()));
    EXPECT_EQ(reject({.n = 2}), ReasonCode::ParameterOutOfRange);
    EXPECT_EQ(reject({.n = 0}), ReasonCode::ParameterOutOfRange);
    EXPECT_EQ(reject({.stream = true}), ReasonCode::StreamNotAllowed);
}

TEST(CoreRequestParams, KeepsResponseFormat) {
    const auto params =
        pc::RequestParams::create({.response_format = pc::ResponseFormat::JsonObject}, pc::OutputTokenCap::standard());
    ASSERT_TRUE(params);
    EXPECT_EQ(params->response_format(), pc::ResponseFormat::JsonObject);
    EXPECT_FALSE(params->temperature());
}
