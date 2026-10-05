#include "prompt_airlock/core/merge.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include "prng.hpp"

namespace pc = prompt_airlock::core;

namespace {

constexpr std::size_t text_size = 64;
constexpr std::uint32_t segment_count = 3;

const std::string& text() {
    static const std::string value(text_size, 'x');
    return value;
}

std::vector<pc::EntitySpan> random_spans(pa_test::SplitMix64& rng) {
    std::vector<pc::EntitySpan> out;
    const auto count = rng.below(40);
    for (std::uint64_t i = 0; i < count; ++i) {
        const auto begin = rng.below(text_size - 1);
        const auto end = begin + 1 + rng.below(std::min<std::uint64_t>(12, text_size - begin));
        const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{end});
        const auto type = static_cast<pc::EntityType>(rng.below(pc::entity_type_count));
        const auto detector = static_cast<pc::DetectorKind>(rng.below(6));
        out.push_back(*pc::EntitySpan::make(text(), pc::SegmentIndex{static_cast<std::uint32_t>(rng.below(segment_count))},
                                            span, type, detector));
    }
    return out;
}

void shuffle(std::vector<pc::EntitySpan>& spans, pa_test::SplitMix64& rng) {
    for (std::size_t i = spans.size(); i > 1; --i) {
        std::swap(spans[i - 1], spans[rng.below(i)]);
    }
}

}  // namespace

TEST(CoreMergeProperty, MergedOutputIsCanonical) {
    const auto config = pa_test::property_config();
    for (const auto seed : config.seeds) {
        pa_test::SplitMix64 rng(seed);
        for (std::size_t iteration = 0; iteration < config.iterations; ++iteration) {
            auto input = random_spans(rng);
            SCOPED_TRACE(testing::Message() << "seed=" << seed << " iteration=" << iteration);
            const auto out = pc::merge_entities(input);

            // 정렬되어 있고, 같은 segment 안에서 서로 겹치지 않는다.
            for (std::size_t i = 1; i < out.size(); ++i) {
                const auto& prev = out[i - 1];
                const auto& cur = out[i];
                ASSERT_TRUE(prev.segment < cur.segment ||
                            (prev.segment == cur.segment && prev.span.end() <= cur.span.begin()));
            }

            // 입력 하나는 정확히 한 덩어리 안에 들어가고, 덩어리의 처리·종류는 들어간 입력에서만 나온다.
            std::vector<pc::Action> action(out.size(), pc::Action::Pass);
            std::vector<pc::EntityTypeSet> types(out.size());
            for (const auto& entity : input) {
                int owners = 0;
                for (std::size_t k = 0; k < out.size(); ++k) {
                    if (out[k].segment == entity.segment() && out[k].span.contains(entity.span())) {
                        ++owners;
                        action[k] = pc::stricter(action[k], pc::default_action(entity.type()));
                        types[k].insert(entity.type());
                    }
                }
                ASSERT_EQ(owners, 1);
            }

            // 덩어리의 모든 byte 는 어떤 입력이 덮는다(합집합 보존).
            for (std::size_t k = 0; k < out.size(); ++k) {
                EXPECT_EQ(out[k].action, action[k]);
                EXPECT_EQ(out[k].types, types[k]);
                EXPECT_TRUE(out[k].types.contains(out[k].label_type));
                EXPECT_EQ(pc::default_action(out[k].label_type), out[k].action);
                for (auto b = out[k].span.begin().value(); b < out[k].span.end().value(); ++b) {
                    const bool covered = std::any_of(input.begin(), input.end(), [&](const pc::EntitySpan& e) {
                        return e.segment() == out[k].segment && e.span().begin().value() <= b &&
                               b < e.span().end().value();
                    });
                    ASSERT_TRUE(covered);
                }
            }

            // 입력 순서와 무관하다.
            shuffle(input, rng);
            EXPECT_EQ(pc::merge_entities(input), out);
        }
    }
}
