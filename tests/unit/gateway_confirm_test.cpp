// 확인 표지는 같은 본문·출처에서 한 번만, 기한 안에서만 사용한다.
#include "prompt_airlock/gateway/confirm.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <barrier>
#include <future>
#include <string>
#include <thread>
#include <vector>

namespace gw = prompt_airlock::gateway;

namespace {
using Clock = gw::ConfirmLedger::Clock;

TEST(ConfirmLedger, RedeemsOnceForTheSameBodyWithinTheTimeLimit) {
    auto now = Clock::now();
    gw::ConfirmLedger ledger([&] { return now; });
    const auto a = ledger.issue("body-a", "desk-a");
    ASSERT_TRUE(a);
    EXPECT_EQ(a->size(), gw::confirm_token_chars);
    now += gw::confirm_ttl - std::chrono::seconds(1);
    EXPECT_TRUE(ledger.redeem(*a, "body-a", "desk-a"));
    EXPECT_FALSE(ledger.redeem(*a, "body-a", "desk-a"));
    const auto b = ledger.issue("body-b", "desk-a");
    EXPECT_FALSE(ledger.redeem(*b, "body-c", "desk-a"));
    EXPECT_FALSE(ledger.redeem(*b, "body-b", "desk-a"));
    const auto c = ledger.issue("body-c", "desk-a");
    now += gw::confirm_ttl;
    EXPECT_FALSE(ledger.redeem(*c, "body-c", "desk-a"));
    EXPECT_FALSE(ledger.redeem("", "body-c", "desk-a"));
}

TEST(ConfirmLedger, StopsIssuingAtCapacityUntilTokensExpire) {
    auto now = Clock::now();
    gw::ConfirmLedger ledger([&] { return now; });
    for (std::size_t i = 0; i < gw::confirm_capacity; ++i) ASSERT_TRUE(ledger.issue("body", "desk-a"));
    EXPECT_FALSE(ledger.issue("body", "desk-a"));
    now += gw::confirm_ttl;
    EXPECT_TRUE(ledger.issue("body", "desk-a"));
}

TEST(ConfirmLedger, AnotherOriginCannotApproveOrConsumeAToken) {
    auto now = Clock::now();
    gw::ConfirmLedger ledger([&] { return now; });
    const auto token = ledger.issue("body", "desk-a");
    ASSERT_TRUE(token);
    EXPECT_FALSE(ledger.approve(*token, "desk-b", [](auto) { return true; }));
    EXPECT_FALSE(ledger.redeem(*token, "body", "desk-b"));
    EXPECT_TRUE(ledger.redeem(*token, "body", "desk-a"));
}

TEST(ConfirmLedger, ApprovalRequiresItsCheckAndIsBoundToBodyOriginAndOriginalExpiry) {
    auto now = Clock::now();
    gw::ConfirmLedger ledger([&] { return now; });
    const auto token = ledger.issue("body", "desk-a");
    ASSERT_TRUE(token);
    EXPECT_FALSE(ledger.approve(*token, "desk-a", [](auto) { return false; }));
    EXPECT_FALSE(ledger.redeem_approved("body", "desk-a"));
    EXPECT_TRUE(ledger.approve(*token, "desk-a", [](auto hash) { return hash == "body"; }));
    EXPECT_FALSE(ledger.approve(*token, "desk-a", [](auto) { return true; }));
    EXPECT_FALSE(ledger.redeem_approved("other", "desk-a"));
    EXPECT_FALSE(ledger.redeem_approved("body", "desk-b"));
    EXPECT_TRUE(ledger.redeem_approved("body", "desk-a"));
    EXPECT_FALSE(ledger.redeem_approved("body", "desk-a"));
    EXPECT_FALSE(ledger.redeem(*token, "body", "desk-a"));
    const auto expiring = ledger.issue("body", "desk-a");
    ASSERT_TRUE(expiring);
    now += gw::confirm_ttl - std::chrono::seconds(1);
    EXPECT_TRUE(ledger.approve(*expiring, "desk-a", [](auto) { return true; }));
    now += std::chrono::seconds(1);
    EXPECT_FALSE(ledger.redeem_approved("body", "desk-a"));
}

TEST(ConfirmLedger, ConcurrentHeaderAndApprovedBodyRedemptionHaveOneWinner) {
    const auto now = Clock::now();
    gw::ConfirmLedger ledger([&] { return now; });
    const auto token = ledger.issue("body", "desk-a");
    ASSERT_TRUE(token);
    ASSERT_TRUE(ledger.approve(*token, "desk-a", [](auto) { return true; }));
    std::barrier start{8};
    std::atomic<int> winners{0};
    std::vector<std::jthread> workers;
    for (int i = 0; i < 8; ++i) workers.emplace_back([&, i] {
        start.arrive_and_wait();
        if (i % 2 == 0 ? ledger.redeem(*token, "body", "desk-a")
                       : ledger.redeem_approved("body", "desk-a")) ++winners;
    });
    workers.clear();
    EXPECT_EQ(winners.load(), 1);
}

TEST(ConfirmLedger, ApprovalCannotRemainValidPastItsAuditCheck) {
    auto now = Clock::now();
    gw::ConfirmLedger ledger([&] { return now; });
    const auto token = ledger.issue("body", "desk-a");
    ASSERT_TRUE(token);
    bool checked = false;
    const bool approved = ledger.approve(*token, "desk-a", [&](auto) {
        checked = true;
        now += gw::confirm_ttl;
        return true;
    });
    EXPECT_TRUE(checked);
    EXPECT_FALSE(approved);
    EXPECT_FALSE(ledger.redeem_approved("body", "desk-a"));
}

TEST(ConfirmLedger, RedemptionCannotUseTimeFromBeforeTheMutexWait) {
    const auto initial = Clock::now();
    std::atomic<Clock::duration::rep> ticks{initial.time_since_epoch().count()};
    gw::ConfirmLedger ledger([&] { return Clock::time_point{Clock::duration{ticks.load()}}; });
    const auto target = ledger.issue("target", "desk-a");
    ASSERT_TRUE(target);
    ASSERT_TRUE(ledger.approve(*target, "desk-a", [](auto) { return true; }));
    ticks = (initial + std::chrono::minutes(1)).time_since_epoch().count();
    const auto blocker = ledger.issue("blocker", "desk-a");
    ASSERT_TRUE(blocker);
    std::promise<void> locked;
    const auto ready = locked.get_future();
    std::promise<void> release;
    const auto gate = release.get_future().share();
    std::atomic<bool> held_approved{false};
    std::atomic<bool> redeemed{true};
    std::jthread holder([&] {
        held_approved = ledger.approve(*blocker, "desk-a", [&](auto) {
            locked.set_value();
            return gate.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
        });
    });
    ASSERT_EQ(ready.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    std::promise<void> entering;
    const auto entered = entering.get_future();
    std::jthread waiter([&] {
        entering.set_value();
        redeemed = ledger.redeem_approved("target", "desk-a");
    });
    ASSERT_EQ(entered.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    ticks = (initial + gw::confirm_ttl).time_since_epoch().count();
    release.set_value();
    holder.join();
    waiter.join();
    EXPECT_TRUE(held_approved.load());
    EXPECT_FALSE(redeemed.load());
}
}  // namespace
