#include "prompt_airlock/gateway/auth.hpp"

#include <gtest/gtest.h>

#include <span>
#include <string>

#include "prompt_airlock/core/sha256.hpp"

namespace {

namespace gw = prompt_airlock::gateway;
using gw::AuthFailure;
using gw::Authenticator;

std::string hash_of(std::string_view token) {
    return prompt_airlock::core::sha256_hex(std::as_bytes(std::span(token.data(), token.size())));
}

class GatewayAuth : public ::testing::Test {
protected:
    Authenticator auth_{{{"dept-a", hash_of("token-a"), prompt_airlock::core::GradePolicy::OOnly},
                         {"dept-b", hash_of("token-b"), prompt_airlock::core::GradePolicy::Declare}}};
    Authenticator::Clock::time_point now_{};
};

TEST_F(GatewayAuth, AcceptsRegisteredTokens) {
    const auto a = auth_.authenticate("Bearer token-a", "10.0.0.1", now_);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ((*a)->name, "dept-a");
    const auto b = auth_.authenticate("bearer token-b", "10.0.0.1", now_);  // 인증 방식 이름은 대소문자를 가리지 않는다
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ((*b)->name, "dept-b");
}

TEST_F(GatewayAuth, RejectsMissingMalformedAndUnknown) {
    EXPECT_EQ(auth_.authenticate("", "c", now_).error(), AuthFailure::Missing);
    EXPECT_EQ(auth_.authenticate("Basic dXNlcjpwdw==", "c", now_).error(), AuthFailure::Malformed);
    EXPECT_EQ(auth_.authenticate("Bearer ", "c", now_).error(), AuthFailure::Malformed);
    EXPECT_EQ(auth_.authenticate("Bearer token a", "c", now_).error(), AuthFailure::Malformed);
    EXPECT_EQ(auth_.authenticate("Bearer " + std::string(257, 'x'), "d", now_).error(), AuthFailure::Malformed);
    EXPECT_EQ(auth_.authenticate("Bearer token-c", "e", now_).error(), AuthFailure::Unknown);
    // 해시 값 자체를 token 으로 내도 통과하지 않는다
    EXPECT_EQ(auth_.authenticate("Bearer " + hash_of("token-a"), "e", now_).error(), AuthFailure::Unknown);
}

TEST_F(GatewayAuth, LocksClientAfterRepeatedFailures) {
    for (int i = 0; i < Authenticator::max_failures; ++i) {
        EXPECT_EQ(auth_.authenticate("Bearer wrong", "10.0.0.9", now_).error(), AuthFailure::Unknown);
    }
    // 잠긴 동안에는 맞는 token 도 거절한다. 다른 주소는 영향을 받지 않는다.
    EXPECT_EQ(auth_.authenticate("Bearer token-a", "10.0.0.9", now_).error(), AuthFailure::Locked);
    EXPECT_TRUE(auth_.authenticate("Bearer token-a", "10.0.0.10", now_).has_value());
    const auto later = now_ + Authenticator::lock_duration + std::chrono::seconds(1);
    EXPECT_TRUE(auth_.authenticate("Bearer token-a", "10.0.0.9", later).has_value());
}

TEST_F(GatewayAuth, SuccessResetsFailureCount) {
    for (int i = 0; i < Authenticator::max_failures - 1; ++i) {
        (void)auth_.authenticate("Bearer wrong", "10.0.0.7", now_);
    }
    ASSERT_TRUE(auth_.authenticate("Bearer token-a", "10.0.0.7", now_).has_value());
    EXPECT_EQ(auth_.authenticate("Bearer wrong", "10.0.0.7", now_).error(), AuthFailure::Unknown);
    EXPECT_TRUE(auth_.authenticate("Bearer token-a", "10.0.0.7", now_).has_value());
}

}  // namespace
