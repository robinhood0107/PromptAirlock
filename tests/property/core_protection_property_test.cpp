// 보호·복원 property(spec §42): 같은 범위 같은 값 → 같은 token, 다른 값 → 다른 token,
// token 에 원문 조각 없음, 보호 후 텍스트에 원문 없음, restore(protect(x)) == x, 복원 값 ⊆ 같은 범위 입력 값,
// 차단 종류가 있으면 언제나 거절.
#include "prompt_airlock/core/grade.hpp"
#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/privacy.hpp"
#include "prompt_airlock/core/residual.hpp"
#include "prompt_airlock/core/restore.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "fake_vault.hpp"
#include "prng.hpp"

namespace pc = prompt_airlock::core;
using pc::EntityType;

namespace {

// 값은 A 음절로, 채움 말은 B 단어로 만들어 서로 겹치지 않는다(합성 데이터).
constexpr std::array<std::string_view, 8> value_syllables = {"가", "나", "다", "라", "마", "바", "사", "아"};
constexpr std::array<std::string_view, 6> filler_words = {"하루", "오늘", "일정", "회의", "보고", "확인"};
constexpr std::array<EntityType, 7> tokenize_types = {EntityType::Person,    EntityType::Organization,
                                                      EntityType::KoreanPhone, EntityType::KoreanBusinessNo,
                                                      EntityType::Email,     EntityType::IpAddress,
                                                      EntityType::InternalTerm};

struct Sample {
    std::string text;
    std::vector<pc::EntitySpan> detected;
    std::vector<std::pair<EntityType, std::string>> values;  // detected 와 같은 순서
};

Sample random_sample(pa_test::SplitMix64& rng, bool allow_block) {
    Sample sample;
    // 같은 값이 다시 나오도록 작은 값 풀을 먼저 만든다.
    std::vector<std::pair<EntityType, std::string>> pool;
    const auto pool_size = 1 + rng.below(4);
    for (std::uint64_t i = 0; i < pool_size; ++i) {
        std::string value;
        const auto syllables = 2 + rng.below(2);
        for (std::uint64_t k = 0; k < syllables; ++k) {
            value += value_syllables[rng.below(value_syllables.size())];
        }
        pool.emplace_back(tokenize_types[rng.below(tokenize_types.size())], value);
    }
    const auto pieces = 1 + rng.below(8);
    for (std::uint64_t i = 0; i < pieces; ++i) {
        if (rng.chance(1, 2)) {
            sample.text += filler_words[rng.below(filler_words.size())];
        } else {
            auto [type, value] = pool[rng.below(pool.size())];
            if (allow_block && rng.chance(1, 10)) {
                type = EntityType::CardNumber;
            }
            const auto begin = sample.text.size();
            sample.text += value;
            const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{sample.text.size()});
            sample.detected.push_back(
                *pc::EntitySpan::make(sample.text, pc::SegmentIndex{0}, span, type, pc::DetectorKind::Pattern));
            sample.values.emplace_back(type, value);
        }
        sample.text += ' ';
    }
    return sample;
}

std::expected<pc::PolicyCheckedPrompt, pc::Rejection> check(const Sample& sample) {
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(sample.text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts));
    auto raw = pc::RawPrompt::create(*std::move(builder).build(),
                                     *pc::RequestParams::create({}, pc::OutputTokenCap::standard()),
                                     *pc::resolve_grade(pc::GradePolicy::OOnly, {}));
    // 탐지 위치는 텍스트를 만들던 도중의 문자열 기준이지만, 뒤에 덧붙이기만 했으므로 최종 텍스트에서도 같다.
    return pc::check_policy(std::move(raw), sample.detected, pc::Policy::standard());
}

}  // namespace

TEST(CoreProtectionProperty, ConsistentLeakFreeAndRoundTrips) {
    const auto config = pa_test::property_config();
    for (const auto seed : config.seeds) {
        pa_test::SplitMix64 rng(seed);
        for (std::size_t iteration = 0; iteration < config.iterations; ++iteration) {
            const auto sample = random_sample(rng, false);
            SCOPED_TRACE(testing::Message() << "seed=" << seed << " iteration=" << iteration << " text=" << sample.text);
            pa_test::FakeVault vault(seed ^ iteration);
            auto protected_prompt = pc::protect(*check(sample), vault);
            ASSERT_TRUE(protected_prompt);
            const std::string out(protected_prompt->document().segments()[0].text());

            // 보호 후 텍스트에 원문 값이 없다. R 에 원문 연속 4자가 없음은 apply_protection 이 확인하며 통과가 그 증거다.
            for (const auto& [type, value] : sample.values) {
                ASSERT_EQ(out.find(value), std::string::npos);
            }
            // 같은 (종류, 값) ↔ 같은 token. 합쳐진 탐지 결과 순서와 token 순서가 같다.
            const auto tokens = pc::scan_tokens(out);
            const auto entities = pc::merge_entities(sample.detected);
            ASSERT_EQ(tokens.size(), entities.size());
            std::map<std::pair<EntityType, std::string>, std::string> token_of;
            std::set<std::string> distinct_tokens;
            for (std::size_t i = 0; i < tokens.size(); ++i) {
                const auto value = sample.text.substr(entities[i].span.begin().value(), entities[i].span.size());
                const auto [it, inserted] =
                    token_of.try_emplace({entities[i].label_type, value}, std::string(tokens[i].token.text()));
                ASSERT_EQ(it->second, tokens[i].token.text());
                distinct_tokens.insert(std::string(tokens[i].token.text()));
            }
            ASSERT_EQ(distinct_tokens.size(), token_of.size());

            // restore(protect(x)) == x: 응답이 보호 후 텍스트를 그대로 돌려줄 때.
            auto verified = pc::verify_residual(std::move(*protected_prompt), {});
            ASSERT_TRUE(verified);
            auto checked_response = pc::check_response(pc::SensitiveText::copy_of(out), {});
            const auto plan = pc::plan_restore(*checked_response);
            ASSERT_TRUE(plan);
            const auto restored = pc::apply_restore(std::move(*checked_response), *plan, vault);
            ASSERT_TRUE(restored);
            ASSERT_EQ(restored->view(), sample.text);
        }
    }
}

TEST(CoreProtectionProperty, RestoredValuesComeOnlyFromThisRequest) {
    const auto config = pa_test::property_config();
    for (const auto seed : config.seeds) {
        pa_test::SplitMix64 rng(seed);
        for (std::size_t iteration = 0; iteration < config.iterations; ++iteration) {
            const auto sample = random_sample(rng, false);
            SCOPED_TRACE(testing::Message() << "seed=" << seed << " iteration=" << iteration);
            pa_test::FakeVault vault(seed + iteration);
            auto protected_prompt = pc::protect(*check(sample), vault);
            ASSERT_TRUE(protected_prompt);
            const auto tokens = pc::scan_tokens(protected_prompt->document().segments()[0].text());
            if (tokens.empty()) {
                continue;
            }
            // 모델이 token 일부를 골라 순서를 바꿔 답했다고 가정한다.
            std::string response;
            std::vector<std::size_t> picked;
            for (std::uint64_t k = 0, n = 1 + rng.below(4); k < n; ++k) {
                picked.push_back(rng.below(tokens.size()));
                response += std::string(tokens[picked.back()].token.text()) + " / ";
            }
            auto checked_response = pc::check_response(pc::SensitiveText::copy_of(response), {});
            const auto plan = pc::plan_restore(*checked_response);
            const auto restored = pc::apply_restore(std::move(*checked_response), *plan, vault);
            ASSERT_TRUE(restored);
            const auto entities = pc::merge_entities(sample.detected);
            std::string expected;
            for (const auto index : picked) {
                expected += sample.text.substr(entities[index].span.begin().value(), entities[index].span.size()) + " / ";
            }
            ASSERT_EQ(restored->view(), expected);
        }
    }
}

TEST(CoreProtectionProperty, BlockTypeAlwaysRejected) {
    const auto config = pa_test::property_config();
    for (const auto seed : config.seeds) {
        pa_test::SplitMix64 rng(seed);
        for (std::size_t iteration = 0; iteration < config.iterations; ++iteration) {
            const auto sample = random_sample(rng, true);
            const bool has_block = std::any_of(sample.values.begin(), sample.values.end(),
                                               [](const auto& v) { return v.first == EntityType::CardNumber; });
            const auto checked = check(sample);
            ASSERT_EQ(checked.has_value(), !has_block) << "seed=" << seed << " iteration=" << iteration;
            if (has_block) {
                ASSERT_EQ(checked.error().code(), pc::ReasonCode::EntityBlocked);
            }
        }
    }
}
