// NER worker pool
// - 실제 모델: 여러 요청 스레드가 함께 불러도 결과가 엔진 하나와 같다.
// - 가짜 worker: 막아 둔 worker 로 포화·시간 초과·예외·취소를 순서에 기대지 않고 확인한다.
#include "prompt_airlock/ner/pool.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <stop_token>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "prompt_airlock/ner/engine.hpp"

namespace fs = std::filesystem;
namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pn = prompt_airlock::ner;
using namespace std::chrono_literals;

namespace {

const fs::path model_dir = PA_NER_MODEL_DIR;

// 문이 열릴 때까지 일을 붙잡는 가짜 worker. 시작한 일 수를 센다.
class GateWorker final : public pn::NerWorker {
public:
    std::expected<std::vector<pc::EntitySpan>, pc::DetectError> run(std::string_view, pc::SegmentIndex,
                                                                     const pd::DetectionView&, std::stop_token) override {
        std::unique_lock lock(mutex_);
        ++started_;
        changed_.notify_all();
        changed_.wait(lock, [&] { return open_; });
        return std::vector<pc::EntitySpan>{};
    }

    void open() {
        std::lock_guard lock(mutex_);
        open_ = true;
        changed_.notify_all();
    }

    void wait_started(int count) {
        std::unique_lock lock(mutex_);
        changed_.wait(lock, [&] { return started_ >= count; });
    }

    int started() {
        std::lock_guard lock(mutex_);
        return started_;
    }

private:
    std::mutex mutex_;
    std::condition_variable changed_;
    int started_ = 0;
    bool open_ = false;
};

class ThrowingWorker final : public pn::NerWorker {
public:
    std::expected<std::vector<pc::EntitySpan>, pc::DetectError> run(std::string_view text, pc::SegmentIndex,
                                                                     const pd::DetectionView&, std::stop_token) override {
        if (text == "boom") {
            throw std::runtime_error("모의 실패");
        }
        return std::vector<pc::EntitySpan>{};
    }
};

// 중단 신호가 올 때까지 일을 붙잡는 가짜 worker. 시작한 일과 신호를 받고 끝낸 일을 센다.
class StopWorker final : public pn::NerWorker {
public:
    std::expected<std::vector<pc::EntitySpan>, pc::DetectError> run(std::string_view, pc::SegmentIndex,
                                                                     const pd::DetectionView&,
                                                                     std::stop_token stop) override {
        std::unique_lock lock(mutex_);
        ++started_;
        changed_.notify_all();
        changed_.wait(lock, stop, [] { return false; });
        ++quit_;
        changed_.notify_all();
        return std::vector<pc::EntitySpan>{};
    }

    // 5초 안에 조건이 맞으면 true. 시험이 멈추지 않고 실패하게 한다.
    bool wait_started(int count) {
        std::unique_lock lock(mutex_);
        return changed_.wait_for(lock, 5s, [&] { return started_ >= count; });
    }
    bool wait_quit(int count) {
        std::unique_lock lock(mutex_);
        return changed_.wait_for(lock, 5s, [&] { return quit_ >= count; });
    }
    int started() {
        std::lock_guard lock(mutex_);
        return started_;
    }

private:
    std::mutex mutex_;
    std::condition_variable_any changed_;
    int started_ = 0;
    int quit_ = 0;
};

struct Gated {
    std::shared_ptr<pn::NerPool> pool;
    GateWorker* gate;
};

Gated gated_pool(std::size_t depth, std::chrono::milliseconds wait_limit = pn::ner_wait_limit) {
    auto worker = std::make_unique<GateWorker>();
    auto* gate = worker.get();
    std::vector<std::unique_ptr<pn::NerWorker>> workers;
    workers.push_back(std::move(worker));
    return {*pn::NerPool::start(std::move(workers), depth, wait_limit), gate};
}

const pd::DetectionView& empty_view() {
    static const auto view = *pd::make_view("글");
    return view;
}

}  // namespace

TEST(NerPool, ConcurrentCallersGetTheSameResultAsOneEngine) {
    const auto pool = pn::NerPool::make(model_dir);
    ASSERT_TRUE(pool);
    const std::string text = "이영희가 먼저 갔다. 김민수는 누리별테크에 다닌다.";
    const auto view = pd::make_view(text);
    ASSERT_TRUE(view);
    auto engine = pn::NerEngine::make(model_dir);
    ASSERT_TRUE(engine);
    const auto expected = engine->detect_all(text, pc::SegmentIndex{0}, *view);
    ASSERT_TRUE(expected);
    ASSERT_EQ(expected->size(), 3u);

    // 대기열(16) 안에 들어가도록 8개 스레드가 4번씩 부른다.
    std::atomic<int> same{0};
    std::vector<std::thread> callers;
    for (int t = 0; t < 8; ++t) {
        callers.emplace_back([&] {
            for (int i = 0; i < 4; ++i) {
                const auto found = (*pool)->scan(text, pc::SegmentIndex{0}, *view, {});
                if (found && *found == *expected) {
                    ++same;
                }
            }
        });
    }
    for (auto& c : callers) {
        c.join();
    }
    EXPECT_EQ(same.load(), 32);
}

TEST(NerPool, FullQueueRefusesAtOnceInsteadOfWaiting) {
    // worker 1개를 막아 두고 대기열 1칸을 채운 뒤 하나 더 넣는다.
    auto [pool, gate] = gated_pool(1);
    std::thread running([&] { EXPECT_TRUE(pool->scan("a", pc::SegmentIndex{0}, empty_view(), {})); });
    gate->wait_started(1);
    std::thread queued([&] { EXPECT_TRUE(pool->scan("b", pc::SegmentIndex{0}, empty_view(), {})); });
    while (pool->waiting() != 1) {
        std::this_thread::yield();
    }
    const auto refused = pool->scan("c", pc::SegmentIndex{0}, empty_view(), {});
    ASSERT_FALSE(refused);
    EXPECT_EQ(refused.error(), pc::DetectError::Overloaded);
    gate->open();
    running.join();
    queued.join();
    EXPECT_EQ(gate->started(), 2);  // 거절된 일은 돌지 않았다
}

TEST(NerPool, SlowResultTimesOutAndQueuedWorkIsDropped) {
    auto [pool, gate] = gated_pool(4, 50ms);
    std::thread running([&] {
        const auto r = pool->scan("a", pc::SegmentIndex{0}, empty_view(), {});
        ASSERT_FALSE(r);
        EXPECT_EQ(r.error(), pc::DetectError::Timeout);
    });
    gate->wait_started(1);
    // 이 일은 대기열에서 시간을 넘기고, 넘긴 뒤에는 대기열에서 빠진다.
    const auto late = pool->scan("b", pc::SegmentIndex{0}, empty_view(), {});
    ASSERT_FALSE(late);
    EXPECT_EQ(late.error(), pc::DetectError::Timeout);
    EXPECT_EQ(pool->waiting(), 0u);
    running.join();
    gate->open();
    // pool 이 worker 를 소유하므로 gate 는 pool 이 살아 있을 때만 읽는다. 문을 연 뒤 다음 일이 들어가도
    // 붙잡히지 않는다. 빠진 일 "b" 가 돌았다면 그 사이 시작 수가 2 가 된다.
    EXPECT_TRUE(pool->scan("c", pc::SegmentIndex{0}, empty_view(), {}));
    EXPECT_EQ(gate->started(), 2);  // "a" 와 "c" 만 돌았다
    pool.reset();  // 붙잡힌 일이 끝난 뒤 정상 종료
}

TEST(NerPool, StopReturnsAtOnceAndStopsTheRunningWork) {
    auto worker = std::make_unique<StopWorker>();
    auto* stopper = worker.get();
    std::vector<std::unique_ptr<pn::NerWorker>> workers;
    workers.push_back(std::move(worker));
    const auto pool = *pn::NerPool::start(std::move(workers));
    std::stop_source request;
    std::thread caller([&] {
        const auto r = pool->scan("a", pc::SegmentIndex{0}, empty_view(), request.get_token());
        ASSERT_FALSE(r);
        EXPECT_EQ(r.error(), pc::DetectError::Timeout);
    });
    ASSERT_TRUE(stopper->wait_started(1));
    const auto start = std::chrono::steady_clock::now();
    request.request_stop();
    caller.join();
    EXPECT_LT(std::chrono::steady_clock::now() - start, 1s);  // wait_limit(10초)를 기다리지 않는다
    ASSERT_TRUE(stopper->wait_quit(1));                       // 돌던 일도 중단 신호를 받고 끝났다

    // 이미 포기한 요청은 대기열에 넣지 않는다
    const auto refused = pool->scan("b", pc::SegmentIndex{0}, empty_view(), request.get_token());
    ASSERT_FALSE(refused);
    EXPECT_EQ(refused.error(), pc::DetectError::Timeout);
    EXPECT_EQ(stopper->started(), 1);
}

TEST(NerPool, WorkerExceptionFailsOnlyThatCall) {
    std::vector<std::unique_ptr<pn::NerWorker>> workers;
    workers.push_back(std::make_unique<ThrowingWorker>());
    const auto pool = pn::NerPool::start(std::move(workers));
    ASSERT_TRUE(pool);
    const auto failed = (*pool)->scan("boom", pc::SegmentIndex{0}, empty_view(), {});
    ASSERT_FALSE(failed);
    EXPECT_EQ(failed.error(), pc::DetectError::Unavailable);
    EXPECT_TRUE((*pool)->scan("fine", pc::SegmentIndex{0}, empty_view(), {}));  // worker 는 살아 있다
}

TEST(NerPool, TooManyWindowsIsOverloaded) {
    const auto pool = pn::NerPool::make(model_dir);
    ASSERT_TRUE(pool);
    std::string big;
    for (int i = 0; i < 30'000; ++i) {
        big += "가 ";
    }
    const auto view = pd::make_view(big);
    ASSERT_TRUE(view);
    const auto refused = (*pool)->scan(big, pc::SegmentIndex{0}, *view, {});
    ASSERT_FALSE(refused);
    EXPECT_EQ(refused.error(), pc::DetectError::Overloaded);
}

TEST(NerPool, MissingModelOrBadSetupMeansUnavailable) {
    EXPECT_EQ(pn::NerPool::make(model_dir / "none").error(), pc::DetectError::Unavailable);
    EXPECT_EQ(pn::NerPool::start({}).error(), pc::DetectError::Unavailable);
    std::vector<std::unique_ptr<pn::NerWorker>> one;
    one.push_back(std::make_unique<ThrowingWorker>());
    EXPECT_EQ(pn::NerPool::start(std::move(one), 0).error(), pc::DetectError::Unavailable);
    std::vector<std::unique_ptr<pn::NerWorker>> null_worker(1);
    EXPECT_EQ(pn::NerPool::start(std::move(null_worker)).error(), pc::DetectError::Unavailable);
}
