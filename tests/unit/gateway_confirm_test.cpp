// 경고 확인 표지: 같은 본문에 한 번만, 기한 안에서만, 상한을 넘으면 주지 않는다(ADR 0023).
#include "prompt_airlock/gateway/confirm.hpp"

#include <gtest/gtest.h>

#include <string>

namespace gw = prompt_airlock::gateway;

namespace {

using Clock = gw::ConfirmLedger::Clock;

TEST(ConfirmLedger, RedeemsOnceForTheSameBodyWithinTheTimeLimit) {
    gw::ConfirmLedger ledger;
    const auto now = Clock::now();
    const auto a = ledger.issue("body-a", now);
    ASSERT_TRUE(a);
    EXPECT_EQ(a->size(), gw::confirm_token_chars);
    EXPECT_TRUE(ledger.redeem(*a, "body-a", now + gw::confirm_ttl - std::chrono::seconds(1)));
    EXPECT_FALSE(ledger.redeem(*a, "body-a", now));  // 한 번만

    const auto b = ledger.issue("body-b", now);
    EXPECT_FALSE(ledger.redeem(*b, "body-c", now));  // 다른 본문
    EXPECT_FALSE(ledger.redeem(*b, "body-b", now));  // 틀린 시도에도 지워진다

    const auto c = ledger.issue("body-c", now);
    EXPECT_FALSE(ledger.redeem(*c, "body-c", now + gw::confirm_ttl));  // 기한이 지남
    EXPECT_FALSE(ledger.redeem("", "body-c", now));
}

TEST(ConfirmLedger, StopsIssuingAtCapacityUntilTokensExpire) {
    gw::ConfirmLedger ledger;
    const auto now = Clock::now();
    for (std::size_t i = 0; i < gw::confirm_capacity; ++i) {
        ASSERT_TRUE(ledger.issue("body", now));
    }
    EXPECT_FALSE(ledger.issue("body", now));
    EXPECT_TRUE(ledger.issue("body", now + gw::confirm_ttl));  // 기한이 지난 표지를 치우고 준다
}

}  // namespace
