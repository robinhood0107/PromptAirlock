#include "prompt_airlock/core/sensitive.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string>
#include <type_traits>
#include <utility>

namespace pc = prompt_airlock::core;

static_assert(!std::is_copy_constructible_v<pc::SensitiveText>);
static_assert(!std::is_copy_assignable_v<pc::SensitiveText>);
static_assert(std::is_nothrow_move_constructible_v<pc::SensitiveText>);
static_assert(std::is_nothrow_move_assignable_v<pc::SensitiveText>);
static_assert(!std::is_constructible_v<pc::SensitiveText, const std::string&>);
static_assert(!std::is_constructible_v<pc::SensitiveText, std::string_view>);

TEST(CoreSensitive, SecureWipeZeroesBytes) {
    std::array<char, 8> buffer{'s', 'y', 'n', 't', 'h', 'e', 't', 'c'};
    pc::secure_wipe(buffer);
    EXPECT_TRUE(std::all_of(buffer.begin(), buffer.end(), [](char c) { return c == 0; }));
}

TEST(CoreSensitive, TakesOwnershipAndEmptiesSource) {
    std::string heap(64, 'x');  // SSO 보다 긴 값
    pc::SensitiveText text(std::move(heap));
    EXPECT_EQ(text.size(), 64U);
    EXPECT_TRUE(heap.empty());

    std::string small = "합성값";  // SSO 크기 값
    pc::SensitiveText short_text(std::move(small));
    EXPECT_EQ(short_text.view(), "합성값");
    EXPECT_TRUE(small.empty());
}

TEST(CoreSensitive, MoveLeavesSourceEmpty) {
    auto a = pc::SensitiveText::copy_of("가상 이름");
    pc::SensitiveText b(std::move(a));
    EXPECT_EQ(b.view(), "가상 이름");
    EXPECT_TRUE(a.empty());

    pc::SensitiveText c = pc::SensitiveText::copy_of("다른 값");
    c = std::move(b);
    EXPECT_EQ(c.view(), "가상 이름");
    EXPECT_TRUE(b.empty());
}

TEST(CoreSensitive, CopyOfKeepsBytesExactly) {
    const std::string_view source("a\0b", 3);
    const auto text = pc::SensitiveText::copy_of(source);
    EXPECT_EQ(text.view(), source);
    EXPECT_TRUE(pc::SensitiveText{}.empty());
}
