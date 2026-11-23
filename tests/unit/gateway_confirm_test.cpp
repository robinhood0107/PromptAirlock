// 확인 표지는 같은 본문·출처에서 한 번만, 기한 안에서만 사용한다.
#include "prompt_airlock/gateway/confirm.hpp"

#include <gtest/gtest.h>

#include <algorithm>
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

TEST(ConfirmLedger, ListIsSourceBoundAndDoesNotApproveOrConsumeItems) {
    const auto now = Clock::now();
    gw::ConfirmLedger ledger([&] { return now; });
    const auto pending = ledger.issue("body-pending", "desk-a");
    const auto approved = ledger.issue("body-approved", "desk-a");
    const auto consumed = ledger.issue("body-consumed", "desk-a");
    ASSERT_TRUE(pending);
    ASSERT_TRUE(approved);
    ASSERT_TRUE(consumed);
    ASSERT_TRUE(ledger.approve(*approved, "desk-a", [](auto) { return true; }));
    ASSERT_TRUE(ledger.redeem(*consumed, "body-consumed", "desk-a"));
    ASSERT_TRUE(ledger.issue("body-other", "desk-b"));

    const auto listed = ledger.list_for_origin("desk-a");
    ASSERT_EQ(listed.items.size(), 2u);
    EXPECT_FALSE(listed.truncated);
    const auto pending_item = std::ranges::find(listed.items, *pending, &gw::ConfirmationListItem::approval_mark);
    const auto approved_item = std::ranges::find_if(listed.items, [](const auto& item) { return item.approved; });
    ASSERT_NE(pending_item, listed.items.end());
    ASSERT_NE(approved_item, listed.items.end());
    EXPECT_FALSE(pending_item->approved);
    EXPECT_TRUE(approved_item->approved);
    EXPECT_TRUE(approved_item->approval_mark.empty());
    EXPECT_GT(pending_item->expires_in_seconds, 0u);
    EXPECT_LE(pending_item->expires_in_seconds, gw::confirm_ttl.count() * 60);

    EXPECT_TRUE(ledger.redeem(*pending, "body-pending", "desk-a"));
    EXPECT_TRUE(ledger.redeem_approved("body-approved", "desk-a"));
    EXPECT_TRUE(ledger.list_for_origin("desk-a").items.empty());
}

TEST(ConfirmLedger, ListHasAShortCapAndHidesExpiredItemsWithoutExtendingThem) {
    auto now = Clock::now();
    gw::ConfirmLedger ledger([&] { return now; });
    const auto earliest = ledger.issue("first", "desk-a");
    ASSERT_TRUE(earliest);
    now += std::chrono::minutes(1);
    for (std::size_t i = 0; i < gw::confirmation_list_limit + 5; ++i) {
        ASSERT_TRUE(ledger.issue("body", "desk-a"));
    }
    ASSERT_TRUE(ledger.issue("body", "desk-b"));
    auto listed = ledger.list_for_origin("desk-a");
    ASSERT_EQ(listed.items.size(), gw::confirmation_list_limit);
    EXPECT_TRUE(listed.truncated);
    EXPECT_EQ(listed.items.front().approval_mark, *earliest);
    EXPECT_LT(listed.items.front().expires_in_seconds, listed.items.back().expires_in_seconds);
    for (const auto& item : listed.items) {
        EXPECT_TRUE(gw::valid_confirmation_token(item.approval_mark));
        EXPECT_GT(item.expires_in_seconds, 0u);
        EXPECT_LE(item.expires_in_seconds, gw::confirm_ttl.count() * 60);
    }

    now += gw::confirm_ttl - std::chrono::minutes(1) - std::chrono::seconds(1);
    listed = ledger.list_for_origin("desk-a");
    ASSERT_EQ(listed.items.size(), gw::confirmation_list_limit);
    EXPECT_TRUE(listed.truncated);
    EXPECT_EQ(listed.items.front().approval_mark, *earliest);
    EXPECT_EQ(listed.items.front().expires_in_seconds, 1u);
    now += std::chrono::seconds(1);
    listed = ledger.list_for_origin("desk-a");
    ASSERT_EQ(listed.items.size(), gw::confirmation_list_limit);
    EXPECT_TRUE(listed.truncated);
    EXPECT_NE(listed.items.front().approval_mark, *earliest);
    now += std::chrono::minutes(1);
    listed = ledger.list_for_origin("desk-a");
    EXPECT_TRUE(listed.items.empty());
    EXPECT_FALSE(listed.truncated);
}

TEST(ConfirmLedger, ConcurrentListingWithApprovalAndConsumptionIsSafe) {
    const auto now = Clock::now();
    gw::ConfirmLedger ledger([&] { return now; });
    std::vector<std::string> tokens;
    for (int i = 0; i < 64; ++i) {
        const auto token = ledger.issue("body", "desk-a");
        ASSERT_TRUE(token);
        tokens.push_back(*token);
    }
    ASSERT_TRUE(ledger.issue("body", "desk-b"));
    std::barrier start(4);
    std::atomic<bool> failed{false};
    auto reader = [&] {
        start.arrive_and_wait();
        for (int i = 0; i < 100; ++i) {
            const auto snapshot = ledger.list_for_origin("desk-a");
            if (snapshot.items.size() > gw::confirmation_list_limit) failed = true;
            for (const auto& item : snapshot.items) {
                if (item.expires_in_seconds == 0 ||
                    (item.approved ? !item.approval_mark.empty()
                                   : std::ranges::find(tokens, item.approval_mark) == tokens.end())) failed = true;
            }
        }
    };
    std::jthread first_reader(reader);
    std::jthread second_reader(reader);
    std::jthread writer([&] {
        start.arrive_and_wait();
        for (const auto& token : tokens) {
            if (ledger.approve(token, "desk-a", [](auto) { return true; })) {
                (void)ledger.redeem_approved("body", "desk-a");
            }
        }
    });
    start.arrive_and_wait();
    first_reader.join();
    second_reader.join();
    writer.join();
    EXPECT_FALSE(failed.load());
}
}  // namespace
