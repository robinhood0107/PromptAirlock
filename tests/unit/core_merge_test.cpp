#include "prompt_airlock/core/merge.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace pc = prompt_airlock::core;
using pc::Action;
using pc::EntityType;

namespace {

// 시험용 segment 텍스트. ASCII 라 모든 byte 가 문자 경계다.
const std::string& text() {
    static const std::string value(64, 'x');
    return value;
}

pc::EntitySpan entity(std::uint32_t segment, std::size_t begin, std::size_t end, EntityType type,
                      pc::DetectorKind detector = pc::DetectorKind::Pattern) {
    const auto s = *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{end});
    return *pc::EntitySpan::make(text(), pc::SegmentIndex{segment}, s, type, detector);
}

pc::ByteSpan span(std::size_t begin, std::size_t end) {
    return *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{end});
}

}  // namespace

TEST(CoreMerge, EmptyInputGivesEmptyOutput) { EXPECT_TRUE(pc::merge_entities({}).empty()); }

TEST(CoreMerge, KeepsSeparateAndTouchingSpans) {
    const std::vector<pc::EntitySpan> in{entity(0, 0, 4, EntityType::Person), entity(0, 4, 8, EntityType::Email),
                                         entity(0, 10, 12, EntityType::Person)};
    const auto out = pc::merge_entities(in);
    ASSERT_EQ(out.size(), 3U);
    EXPECT_EQ(out[0].span, span(0, 4));
    EXPECT_EQ(out[1].span, span(4, 8));
    EXPECT_EQ(out[2].span, span(10, 12));
}

TEST(CoreMerge, OverlapTakesStricterAction) {
    const std::vector<pc::EntitySpan> in{entity(0, 2, 10, EntityType::Person, pc::DetectorKind::Ner),
                                         entity(0, 5, 14, EntityType::BankAccount)};
    const auto out = pc::merge_entities(in);
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].span, span(2, 14));
    EXPECT_EQ(out[0].action, Action::Block);
    EXPECT_EQ(out[0].label_type, EntityType::BankAccount);
    EXPECT_TRUE(out[0].types.contains(EntityType::Person));
    EXPECT_TRUE(out[0].types.contains(EntityType::BankAccount));
}

TEST(CoreMerge, ContainedAndDuplicateSpansMerge) {
    const std::vector<pc::EntitySpan> in{entity(0, 0, 20, EntityType::Organization),
                                         entity(0, 3, 6, EntityType::Person),
                                         entity(0, 3, 6, EntityType::Person, pc::DetectorKind::Ner)};
    const auto out = pc::merge_entities(in);
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].span, span(0, 20));
    EXPECT_EQ(out[0].action, Action::Tokenize);
    EXPECT_EQ(out[0].label_type, EntityType::Organization);
}

TEST(CoreMerge, ChainOfOverlapsBecomesOne) {
    const std::vector<pc::EntitySpan> in{entity(0, 0, 3, EntityType::Person), entity(0, 2, 5, EntityType::Person),
                                         entity(0, 4, 7, EntityType::Email)};
    const auto out = pc::merge_entities(in);
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].span, span(0, 7));
    EXPECT_EQ(out[0].label_type, EntityType::Email);  // 형식 있는 값이 이름보다 먼저
}

TEST(CoreMerge, DifferentSegmentsNeverMerge) {
    const std::vector<pc::EntitySpan> in{entity(1, 0, 5, EntityType::Person), entity(0, 0, 5, EntityType::Person)};
    const auto out = pc::merge_entities(in);
    ASSERT_EQ(out.size(), 2U);
    EXPECT_EQ(out[0].segment, pc::SegmentIndex{0});
    EXPECT_EQ(out[1].segment, pc::SegmentIndex{1});
}

TEST(CoreMerge, BlockLabelUsesEnumOrder) {
    const std::vector<pc::EntitySpan> in{entity(0, 0, 8, EntityType::CardNumber), entity(0, 1, 8, EntityType::KoreanRrn)};
    const auto out = pc::merge_entities(in);
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0].label_type, EntityType::KoreanRrn);
}

TEST(CoreMerge, ResultIndependentOfInputOrder) {
    std::vector<pc::EntitySpan> in{entity(0, 5, 9, EntityType::KoreanPhone), entity(0, 0, 3, EntityType::Person),
                                   entity(0, 2, 6, EntityType::Email), entity(2, 1, 4, EntityType::ApiKey),
                                   entity(0, 20, 30, EntityType::InternalTerm)};
    const auto reference = pc::merge_entities(in);
    std::sort(in.begin(), in.end());
    do {
        EXPECT_EQ(pc::merge_entities(in), reference);
    } while (std::next_permutation(in.begin(), in.end()));
}
