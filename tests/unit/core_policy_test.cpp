#include "prompt_airlock/core/policy.hpp"

#include <gtest/gtest.h>

#include <type_traits>

namespace pc = prompt_airlock::core;

// 요청 중 정책이 바뀌지 않는다: 대입·기본 생성 불가, 복사(스냅샷 공유)만 된다.
static_assert(!std::is_copy_assignable_v<pc::Policy>);
static_assert(!std::is_move_assignable_v<pc::Policy>);
static_assert(!std::is_default_constructible_v<pc::Policy>);
static_assert(std::is_nothrow_copy_constructible_v<pc::Policy>);

TEST(CorePolicy, StandardUsesFixedTableAndLimits) {
    constexpr auto policy = pc::Policy::standard();
    for (const auto type : pc::all_entity_types()) {
        EXPECT_EQ(policy.action_for(type), pc::default_action(type));
    }
    EXPECT_EQ(policy.max_prompt_bytes(), 65536U);
    EXPECT_EQ(policy.max_entities(), 512U);
    EXPECT_EQ(policy.output_token_cap().value(), 4096U);
}

TEST(CorePolicy, OnlyOutputCapIsAdjustable) {
    const auto policy = pc::Policy::standard(*pc::OutputTokenCap::make(16384));
    EXPECT_EQ(policy.output_token_cap().value(), 16384U);
    EXPECT_EQ(policy.max_prompt_bytes(), 65536U);
}
