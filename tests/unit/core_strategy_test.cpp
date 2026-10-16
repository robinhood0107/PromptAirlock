#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/research.hpp"
#include "prompt_airlock/core/strategy.hpp"

#include <gtest/gtest.h>

#include <type_traits>

namespace pc = prompt_airlock::core;
using pc::PrivacyStrategyKind;

// 연구용 열쇠는 기본 생성할 수 없다. 만드는 함수는 연구 라이브러리에만 있다(이 시험은 그것을 링크한다).
static_assert(!std::is_default_constructible_v<pc::ResearchOnly>);
static_assert(!std::is_constructible_v<pc::PrivacyStrategy, PrivacyStrategyKind>);

TEST(CoreStrategy, StandardPolicyAlwaysUsesUniquePseudonym) {
    EXPECT_EQ(pc::Policy::standard().strategy().kind(), PrivacyStrategyKind::UniquePseudonym);
    EXPECT_EQ(pc::Policy::standard(*pc::OutputTokenCap::make(100)).strategy().kind(),
              PrivacyStrategyKind::UniquePseudonym);
}

TEST(CoreStrategy, ResearchPolicyCanChooseAnyStrategy) {
    const auto key = pc::make_research_only();
    EXPECT_EQ(pc::Policy::research(key, pc::PrivacyStrategy::no_protection(key)).strategy().kind(),
              PrivacyStrategyKind::NoProtection);
    EXPECT_EQ(pc::Policy::research(key, pc::PrivacyStrategy::redaction()).strategy().kind(),
              PrivacyStrategyKind::Redaction);
    const auto masked = pc::Policy::research(key, pc::PrivacyStrategy::type_mask());
    EXPECT_EQ(masked.strategy().kind(), PrivacyStrategyKind::TypeMask);
    EXPECT_EQ(masked.max_prompt_bytes(), 65536U);  // 연구용이어도 한도와 처리 표는 같다
}
