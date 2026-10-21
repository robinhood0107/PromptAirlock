// 창 분할: 창마다 한도 안, 빠지는 토큰 없음, 문장 끝 우선, 긴 문장은 겹쳐 밀기, 창 수 상한.
#include "prompt_airlock/ner/windows.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace pn = prompt_airlock::ner;

namespace {

using Windows = std::vector<pn::TokenWindow>;

// 모든 토큰이 어떤 창에 들어가고, 문장 끝을 넘지 않는 overlap 길이의 토큰 묶음도 한 창 안에 온전히 들어가는지.
// 이름은 문장 끝을 넘지 않으므로 문장 끝을 가로지르는 묶음은 보지 않는다.
void expect_covers(std::uint32_t tokens, const Windows& windows, const std::vector<std::uint32_t>& cuts = {}) {
    for (const auto& w : windows) {
        EXPECT_LT(w.first, w.end);
        EXPECT_LE(w.end - w.first, pn::window_body_tokens);
    }
    const std::uint32_t run = std::min(tokens, pn::window_overlap_tokens);
    for (std::uint32_t i = 0; i + run <= tokens; ++i) {
        if (std::ranges::any_of(cuts, [&](std::uint32_t c) { return i <= c && c + 1 < i + run; })) {
            continue;
        }
        const bool inside = std::ranges::any_of(windows, [&](const auto& w) { return w.first <= i && i + run <= w.end; });
        EXPECT_TRUE(inside) << "토큰 " << i << " 부터 " << run << "개";
    }
}

}  // namespace

TEST(NerWindows, EmptyAndShortInputs) {
    EXPECT_EQ(pn::split_windows(0, {}), Windows{});
    EXPECT_EQ(pn::split_windows(1, {}), (Windows{{0, 1}}));
    EXPECT_EQ(pn::split_windows(pn::window_body_tokens, {}), (Windows{{0, pn::window_body_tokens}}));
}

TEST(NerWindows, CutsAtTheLatestSentenceEndThatFits) {
    // 100 토큰마다 문장 끝. 254 안에서 가장 늦은 끝(199)에서 자른다.
    const std::vector<std::uint32_t> cuts{99, 199, 299, 399, 499};
    const auto windows = pn::split_windows(600, cuts);
    ASSERT_TRUE(windows);
    EXPECT_EQ(*windows, (Windows{{0, 200}, {200, 400}, {400, 600}}));
    expect_covers(600, *windows, cuts);
}

TEST(NerWindows, LongSentenceSlidesWithOverlap) {
    const auto windows = pn::split_windows(300, {});
    ASSERT_TRUE(windows);
    const std::uint32_t next = pn::window_body_tokens - pn::window_overlap_tokens;
    EXPECT_EQ(*windows, (Windows{{0, pn::window_body_tokens}, {next, 300}}));
    expect_covers(300, *windows);
}

TEST(NerWindows, MixedSentencesStillCoverEveryShortRun) {
    // 짧은 문장, 아주 긴 문장, 다시 짧은 문장.
    const std::vector<std::uint32_t> cuts{9, 19, 900, 910, 1500};
    const auto windows = pn::split_windows(1600, cuts);
    ASSERT_TRUE(windows);
    expect_covers(1600, *windows, cuts);
}

TEST(NerWindows, TooManyWindowsIsRefused) {
    // 문장 끝이 없으면 창 하나가 (254 - 32) 토큰씩 나아간다. 128개로 덮을 수 있는 최대 길이.
    const std::uint32_t step = pn::window_body_tokens - pn::window_overlap_tokens;
    const std::uint32_t most = pn::window_body_tokens + step * (pn::max_ner_windows - 1);
    const auto fits = pn::split_windows(most, {});
    ASSERT_TRUE(fits);
    EXPECT_EQ(fits->size(), pn::max_ner_windows);
    EXPECT_FALSE(pn::split_windows(most + 1, {}));
}
