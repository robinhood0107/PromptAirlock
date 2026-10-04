#include "bounded_queue.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

using pa_spike::BoundedQueue;
using pa_spike::QueueError;

TEST(BoundedQueue, TryPushReportsFullWithoutBlocking) {
    BoundedQueue<int> q(2);
    ASSERT_TRUE(q.try_push(1));
    ASSERT_TRUE(q.try_push(2));
    const auto r = q.try_push(3);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.error(), QueueError::Full);
    EXPECT_EQ(q.size(), 2u);
}

TEST(BoundedQueue, ManyProducersConsumersPreserveSum) {
    constexpr int kProducers = 4;
    constexpr int kConsumers = 3;
    constexpr int kPerProducer = 2000;
    BoundedQueue<int> q(8);
    std::atomic<std::int64_t> consumed_sum{0};
    std::atomic<int> consumed_count{0};

    std::vector<std::jthread> consumers;
    for (int c = 0; c < kConsumers; ++c) {
        consumers.emplace_back([&](std::stop_token st) {
            for (;;) {
                auto item = q.pop(st);
                if (!item || !item->has_value()) return;
                consumed_sum += **item;
                ++consumed_count;
            }
        });
    }
    {
        std::vector<std::jthread> producers;
        for (int p = 0; p < kProducers; ++p) {
            producers.emplace_back([&, p](std::stop_token st) {
                for (int i = 1; i <= kPerProducer; ++i) {
                    ASSERT_TRUE(q.push(p * kPerProducer + i, st));
                }
            });
        }
        // jthread 소멸자는 join 전에 request_stop 을 보낸다. 대기 중인 push 가 취소되지 않도록 먼저 join 한다.
        for (auto& t : producers) t.join();
    }
    q.close();
    consumers.clear();

    const std::int64_t n = static_cast<std::int64_t>(kProducers) * kPerProducer;
    EXPECT_EQ(consumed_count.load(), n);
    EXPECT_EQ(consumed_sum.load(), n * (n + 1) / 2);
}

TEST(BoundedQueue, StopRequestUnblocksConsumer) {
    BoundedQueue<int> q(1);
    std::atomic<bool> cancelled{false};
    std::jthread consumer([&](std::stop_token st) {
        auto r = q.pop(st);
        cancelled = !r && r.error() == QueueError::Cancelled;
    });
    // 대기 상태로 들어갈 시간을 준 뒤 취소한다. 동기화 수단이 아니라 시나리오 구성용이다.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    consumer.request_stop();
    consumer.join();
    EXPECT_TRUE(cancelled.load());
}

TEST(BoundedQueue, CloseRejectsNewWorkAndDrains) {
    BoundedQueue<int> q(4);
    ASSERT_TRUE(q.try_push(7));
    q.close();
    const auto rejected = q.try_push(8);
    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error(), QueueError::Closed);
    std::stop_source ss;
    auto first = q.pop(ss.get_token());
    ASSERT_TRUE(first && first->has_value());
    EXPECT_EQ(**first, 7);
    auto end = q.pop(ss.get_token());
    ASSERT_TRUE(end);
    EXPECT_FALSE(end->has_value());
}
