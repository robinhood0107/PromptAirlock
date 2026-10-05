#include "prompt_airlock/core/entity.hpp"

#include <gtest/gtest.h>

#include <string_view>
#include <type_traits>

namespace pc = prompt_airlock::core;
using namespace std::string_view_literals;

static_assert(!std::is_default_constructible_v<pc::EntitySpan>);

namespace {

pc::ByteSpan span(std::size_t begin, std::size_t end) {
    return *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{end});
}

}  // namespace

TEST(CoreEntity, MakesValidSpan) {
    constexpr auto text = "담당 가상인 과장"sv;  // "가상인" = byte 7..16
    const auto entity = pc::EntitySpan::make(text, pc::SegmentIndex{1}, span(7, 16), pc::EntityType::Person,
                                             pc::DetectorKind::Ner);
    ASSERT_TRUE(entity);
    EXPECT_EQ(entity->segment(), pc::SegmentIndex{1});
    EXPECT_EQ(entity->span(), span(7, 16));
    EXPECT_EQ(entity->type(), pc::EntityType::Person);
    EXPECT_EQ(entity->detector(), pc::DetectorKind::Ner);
}

TEST(CoreEntity, RejectsSpanOutsideOrInsideCharacter) {
    constexpr auto text = "가나"sv;  // 6 bytes
    EXPECT_EQ(pc::EntitySpan::make(text, pc::SegmentIndex{0}, span(0, 7), pc::EntityType::Person,
                                   pc::DetectorKind::Ner)
                  .error(),
              pc::InputError::OffsetOutOfRange);
    EXPECT_EQ(pc::EntitySpan::make(text, pc::SegmentIndex{0}, span(1, 3), pc::EntityType::Person,
                                   pc::DetectorKind::Ner)
                  .error(),
              pc::InputError::NotCodepointBoundary);
}

TEST(CoreEntity, RejectsOutOfRangeEnums) {
    constexpr auto text = "abc"sv;
    EXPECT_EQ(pc::EntitySpan::make(text, pc::SegmentIndex{0}, span(0, 1), static_cast<pc::EntityType>(17),
                                   pc::DetectorKind::Pattern)
                  .error(),
              pc::InputError::ValueOutOfRange);
    EXPECT_EQ(pc::EntitySpan::make(text, pc::SegmentIndex{0}, span(0, 1), pc::EntityType::Email,
                                   static_cast<pc::DetectorKind>(6))
                  .error(),
              pc::InputError::ValueOutOfRange);
}

TEST(CoreEntity, OrdersBySegmentThenSpan) {
    constexpr auto text = "abcdef"sv;
    const auto a = *pc::EntitySpan::make(text, pc::SegmentIndex{0}, span(3, 4), pc::EntityType::Email,
                                         pc::DetectorKind::Pattern);
    const auto b = *pc::EntitySpan::make(text, pc::SegmentIndex{1}, span(0, 1), pc::EntityType::Email,
                                         pc::DetectorKind::Pattern);
    const auto c = *pc::EntitySpan::make(text, pc::SegmentIndex{0}, span(1, 2), pc::EntityType::Email,
                                         pc::DetectorKind::Pattern);
    EXPECT_LT(c, a);
    EXPECT_LT(a, b);
}
