#include "prompt_airlock/core/offset.hpp"

#include <gtest/gtest.h>

#include <type_traits>

namespace pc = prompt_airlock::core;

// 위치 종류끼리는 변환·대입이 되지 않는다. 비교 불가는 compile-fail 시험이 맡는다.
static_assert(!std::is_convertible_v<pc::Utf8ByteOffset, pc::CodepointOffset>);
static_assert(!std::is_convertible_v<pc::CodepointOffset, pc::Utf8ByteOffset>);
static_assert(!std::is_convertible_v<pc::TokenOffset, pc::Utf8ByteOffset>);
static_assert(!std::is_convertible_v<std::size_t, pc::Utf8ByteOffset>);
static_assert(!std::is_assignable_v<pc::Utf8ByteOffset&, pc::CodepointOffset>);
static_assert(!std::is_constructible_v<pc::Utf8ByteOffset, pc::CodepointOffset>);
static_assert(std::is_trivially_copyable_v<pc::ByteSpan>);

TEST(CoreOffset, ComparesWithinSameKind) {
    EXPECT_LT(pc::Utf8ByteOffset{1}, pc::Utf8ByteOffset{2});
    EXPECT_EQ(pc::CodepointOffset{3}, pc::CodepointOffset{3});
    EXPECT_EQ(pc::Utf8ByteOffset{}.value(), 0U);
}

TEST(CoreOffset, ByteSpanRejectsEmptyOrReversed) {
    EXPECT_EQ(pc::ByteSpan::make(pc::Utf8ByteOffset{3}, pc::Utf8ByteOffset{3}).error(), pc::InputError::EmptySpan);
    EXPECT_EQ(pc::ByteSpan::make(pc::Utf8ByteOffset{4}, pc::Utf8ByteOffset{3}).error(), pc::InputError::EmptySpan);
    const auto span = pc::ByteSpan::make(pc::Utf8ByteOffset{3}, pc::Utf8ByteOffset{7});
    ASSERT_TRUE(span);
    EXPECT_EQ(span->size(), 4U);
}

TEST(CoreOffset, OverlapExcludesTouching) {
    const auto a = *pc::ByteSpan::make(pc::Utf8ByteOffset{0}, pc::Utf8ByteOffset{3});
    const auto b = *pc::ByteSpan::make(pc::Utf8ByteOffset{3}, pc::Utf8ByteOffset{6});
    const auto c = *pc::ByteSpan::make(pc::Utf8ByteOffset{2}, pc::Utf8ByteOffset{4});
    EXPECT_FALSE(a.overlaps(b));
    EXPECT_TRUE(a.overlaps(c));
    EXPECT_TRUE(c.overlaps(b));
}

TEST(CoreOffset, HullAndContains) {
    const auto a = *pc::ByteSpan::make(pc::Utf8ByteOffset{5}, pc::Utf8ByteOffset{8});
    const auto b = *pc::ByteSpan::make(pc::Utf8ByteOffset{2}, pc::Utf8ByteOffset{6});
    const auto h = pc::ByteSpan::hull(a, b);
    EXPECT_EQ(h.begin(), pc::Utf8ByteOffset{2});
    EXPECT_EQ(h.end(), pc::Utf8ByteOffset{8});
    EXPECT_TRUE(h.contains(a));
    EXPECT_TRUE(h.contains(b));
    EXPECT_FALSE(a.contains(h));
}
