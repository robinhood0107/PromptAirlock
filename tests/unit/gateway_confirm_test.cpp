// 경고 확인 표지: 같은 본문에 한 번만, 기한 안에서만, 상한을 넘으면 주지 않는다(ADR 0023).
#include "prompt_airlock/gateway/confirm.hpp"

#include <gtest/gtest.h>

#include <string>
#include <atomic>
#include <barrier>
#include <thread>
#include <vector>

namespace gw = prompt_airlock::gateway;

namespace {

using Clock = gw::ConfirmLedger::Clock;

TEST(ConfirmLedger, RedeemsOnceForTheSameBodyWithinTheTimeLimit) {
    gw::ConfirmLedger ledger;
    const auto now = Clock::now();
    const auto a = ledger.issue("body-a", "desk-a", now);
    ASSERT_TRUE(a);
    EXPECT_EQ(a->size(), gw::confirm_token_chars);
    EXPECT_TRUE(ledger.redeem(*a, "body-a", "desk-a", now + gw::confirm_ttl - std::chrono::seconds(1)));
    EXPECT_FALSE(ledger.redeem(*a, "body-a", "desk-a", now));  // 한 번만

    const auto b = ledger.issue("body-b", "desk-a", now);
    EXPECT_FALSE(ledger.redeem(*b, "body-c", "desk-a", now));  // 다른 본문
    EXPECT_FALSE(ledger.redeem(*b, "body-b", "desk-a", now));  // 틀린 시도에도 지워진다

    const auto c = ledger.issue("body-c", "desk-a", now);
    EXPECT_FALSE(ledger.redeem(*c, "body-c", "desk-a", now + gw::confirm_ttl));  // 기한이 지남
    EXPECT_FALSE(ledger.redeem("", "body-c", "desk-a", now));
}

TEST(ConfirmLedger, StopsIssuingAtCapacityUntilTokensExpire) {
    gw::ConfirmLedger ledger;
    const auto now = Clock::now();
    for (std::size_t i = 0; i < gw::confirm_capacity; ++i) {
        ASSERT_TRUE(ledger.issue("body", "desk-a", now));
    }
    EXPECT_FALSE(ledger.issue("body", "desk-a", now));
    EXPECT_TRUE(ledger.issue("body", "desk-a", now + gw::confirm_ttl));  // 기한이 지난 표지를 치우고 준다
}

TEST(ConfirmLedger, AnotherOriginCannotApproveOrConsumeAToken) {
    gw::ConfirmLedger ledger;
    const auto now = Clock::now();
    const auto token = ledger.issue("body", "desk-a", now);
    ASSERT_TRUE(token);
    EXPECT_FALSE(ledger.approve(*token, "desk-b", now, [](auto) { return true; }));
    EXPECT_FALSE(ledger.redeem(*token, "body", "desk-b", now));
    EXPECT_TRUE(ledger.redeem(*token, "body", "desk-a", now));
}

TEST(ConfirmLedger, ApprovalRequiresItsCheckAndIsBoundToBodyOriginAndOriginalExpiry) {
    gw::ConfirmLedger ledger;
    const auto now = Clock::now();
    const auto token = ledger.issue("body", "desk-a", now);
    ASSERT_TRUE(token);
    EXPECT_FALSE(ledger.approve(*token, "desk-a", now, [](auto) { return false; }));
    EXPECT_FALSE(ledger.redeem_approved("body", "desk-a", now));
    EXPECT_TRUE(ledger.approve(*token, "desk-a", now, [](auto hash) { return hash == "body"; }));
    EXPECT_FALSE(ledger.approve(*token, "desk-a", now, [](auto) { return true; }));
    EXPECT_FALSE(ledger.redeem_approved("other", "desk-a", now));
    EXPECT_FALSE(ledger.redeem_approved("body", "desk-b", now));
    EXPECT_TRUE(ledger.redeem_approved("body", "desk-a", now));
    EXPECT_FALSE(ledger.redeem_approved("body", "desk-a", now));
    EXPECT_FALSE(ledger.redeem(*token, "body", "desk-a", now));
    const auto expiring = ledger.issue("body", "desk-a", now);
    ASSERT_TRUE(expiring);
    EXPECT_TRUE(ledger.approve(*expiring, "desk-a", now + gw::confirm_ttl - std::chrono::seconds(1),
                               [](auto) { return true; }));
    EXPECT_FALSE(ledger.redeem_approved("body", "desk-a", now + gw::confirm_ttl));
}

TEST(ConfirmLedger, ConcurrentHeaderAndApprovedBodyRedemptionHaveOneWinner) {
    gw::ConfirmLedger ledger;
    const auto now = Clock::now();
    const auto token = ledger.issue("body", "desk-a", now);
    ASSERT_TRUE(token);
    ASSERT_TRUE(ledger.approve(*token, "desk-a", now, [](auto) { return true; }));
    std::barrier start{8};
    std::atomic<int> winners{0};
    std::vector<std::jthread> workers;
    for (int i = 0; i < 8; ++i) {
        workers.emplace_back([&, i] {
            start.arrive_and_wait();
            if (i % 2 == 0 ? ledger.redeem(*token, "body", "desk-a", now)
                           : ledger.redeem_approved("body", "desk-a", now)) ++winners;
        });
    }
    workers.clear();
    EXPECT_EQ(winners.load(), 1);
}

}  // namespace
