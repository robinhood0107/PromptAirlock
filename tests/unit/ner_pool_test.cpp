// NER worker pool: 여러 요청 스레드가 함께 불러도 결과가 엔진 하나와 같고, 대기열이 차면 기다리지 않고 거절한다.
#include "prompt_airlock/ner/pool.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <latch>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pn = prompt_airlock::ner;

namespace {

const fs::path model_dir = PA_NER_MODEL_DIR;

std::string long_text() {
    std::string big;
    for (int i = 0; i < 60; ++i) {
        big += "김민수는 누리별테크에 다닌다. ";
    }
    return big;
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
                const auto found = (*pool)->scan(text, pc::SegmentIndex{0}, *view);
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
    // worker 1개, 대기열 1개. 긴 글(여러 창)을 동시에 8개 넣으면 받을 수 있는 것은 실행 중 1 + 대기 1 뿐이다.
    const auto pool = pn::NerPool::make(model_dir, 1, 1);
    ASSERT_TRUE(pool);
    const auto text = long_text();
    const auto view = pd::make_view(text);
    ASSERT_TRUE(view);

    std::atomic<int> ok{0};
    std::atomic<int> overloaded{0};
    std::latch start(8);
    std::vector<std::thread> callers;
    for (int t = 0; t < 8; ++t) {
        callers.emplace_back([&] {
            start.arrive_and_wait();
            const auto found = (*pool)->scan(text, pc::SegmentIndex{0}, *view);
            if (found) {
                ++ok;
            } else if (found.error() == pc::DetectError::Overloaded) {
                ++overloaded;
            }
        });
    }
    for (auto& c : callers) {
        c.join();
    }
    EXPECT_EQ(ok.load() + overloaded.load(), 8);  // 다른 오류는 없다
    EXPECT_GE(ok.load(), 1);
    EXPECT_GE(overloaded.load(), 1);
}

TEST(NerPool, TooManyWindowsIsOverloaded) {
    const auto pool = pn::NerPool::make(model_dir, 1, 1);
    ASSERT_TRUE(pool);
    std::string big;
    for (int i = 0; i < 30'000; ++i) {
        big += "가 ";
    }
    const auto view = pd::make_view(big);
    ASSERT_TRUE(view);
    EXPECT_EQ((*pool)->scan(big, pc::SegmentIndex{0}, *view).error(), pc::DetectError::Overloaded);
}

TEST(NerPool, MissingModelOrBadSizesMeanUnavailable) {
    EXPECT_EQ(pn::NerPool::make(model_dir / "none").error(), pc::DetectError::Unavailable);
    EXPECT_EQ(pn::NerPool::make(model_dir, 0, 1).error(), pc::DetectError::Unavailable);
    EXPECT_EQ(pn::NerPool::make(model_dir, 1, 0).error(), pc::DetectError::Unavailable);
}
