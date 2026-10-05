#include "prompt_airlock/core/utf8.hpp"

#include <gtest/gtest.h>

#include <string_view>

namespace pc = prompt_airlock::core;
using namespace std::string_view_literals;

namespace {

pc::ByteSpan span(std::size_t begin, std::size_t end) {
    return *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{end});
}

}  // namespace

TEST(CoreUtf8, AcceptsValidText) {
    EXPECT_TRUE(pc::validate_utf8(""sv));
    EXPECT_TRUE(pc::validate_utf8("plain ascii"sv));
    EXPECT_TRUE(pc::validate_utf8("가나다 합성 문장"sv));
    EXPECT_TRUE(pc::validate_utf8("\xEF\xBB\xBF" "BOM"sv));               // BOM
    EXPECT_TRUE(pc::validate_utf8("\xE1\x84\x80\xE1\x85\xA1"sv));          // 조합형 자모
    EXPECT_TRUE(pc::validate_utf8("\xF0\x9F\x98\x80"sv));                  // 4바이트 문자
    EXPECT_TRUE(pc::validate_utf8("\xF4\x8F\xBF\xBF"sv));                  // U+10FFFF
    EXPECT_TRUE(pc::validate_utf8("\x00"sv));                              // NUL 도 유효한 UTF-8
}

TEST(CoreUtf8, RejectsOverlong) {
    EXPECT_EQ(pc::validate_utf8("\xC0\x80"sv).error(), pc::InputError::InvalidUtf8);
    EXPECT_EQ(pc::validate_utf8("\xC1\xBF"sv).error(), pc::InputError::InvalidUtf8);
    EXPECT_EQ(pc::validate_utf8("\xE0\x80\x80"sv).error(), pc::InputError::InvalidUtf8);
    EXPECT_EQ(pc::validate_utf8("\xF0\x80\x80\x80"sv).error(), pc::InputError::InvalidUtf8);
}

TEST(CoreUtf8, RejectsSurrogatesAndOutOfRange) {
    EXPECT_EQ(pc::validate_utf8("\xED\xA0\x80"sv).error(), pc::InputError::InvalidUtf8);      // U+D800
    EXPECT_EQ(pc::validate_utf8("\xED\xBF\xBF"sv).error(), pc::InputError::InvalidUtf8);      // U+DFFF
    EXPECT_EQ(pc::validate_utf8("\xF4\x90\x80\x80"sv).error(), pc::InputError::InvalidUtf8);  // U+110000
    EXPECT_EQ(pc::validate_utf8("\xF5\x80\x80\x80"sv).error(), pc::InputError::InvalidUtf8);
    EXPECT_EQ(pc::validate_utf8("\xF8\x88\x80\x80\x80"sv).error(), pc::InputError::InvalidUtf8);
    EXPECT_EQ(pc::validate_utf8("\xFF"sv).error(), pc::InputError::InvalidUtf8);
}

TEST(CoreUtf8, RejectsTruncatedAndStrayContinuation) {
    EXPECT_EQ(pc::validate_utf8("\xEA\xB0"sv).error(), pc::InputError::InvalidUtf8);
    EXPECT_EQ(pc::validate_utf8("ok\xF0\x9F\x98"sv).error(), pc::InputError::InvalidUtf8);
    EXPECT_EQ(pc::validate_utf8("\x80"sv).error(), pc::InputError::InvalidUtf8);
    EXPECT_EQ(pc::validate_utf8("a\xBF" "b"sv).error(), pc::InputError::InvalidUtf8);
    EXPECT_EQ(pc::validate_utf8("\xEA\x41\x80"sv).error(), pc::InputError::InvalidUtf8);
}

TEST(CoreUtf8, DecodeKeepsSourceBytes) {
    const auto units = pc::decode_utf8("a가\xF0\x9F\x98\x80"sv);
    ASSERT_TRUE(units);
    ASSERT_EQ(units->size(), 3U);
    EXPECT_EQ((*units)[0].value, U'a');
    EXPECT_EQ((*units)[0].source, span(0, 1));
    EXPECT_EQ((*units)[1].value, U'가');
    EXPECT_EQ((*units)[1].source, span(1, 4));
    EXPECT_EQ((*units)[2].value, U'\U0001F600');
    EXPECT_EQ((*units)[2].source, span(4, 8));
    EXPECT_FALSE(pc::decode_utf8("\xC0\x80"sv));
}

TEST(CoreUtf8, BoundaryChecks) {
    constexpr auto text = "a가b"sv;  // a(0) 가(1..4) b(4)
    EXPECT_TRUE(pc::is_codepoint_boundary(text, pc::Utf8ByteOffset{0}));
    EXPECT_TRUE(pc::is_codepoint_boundary(text, pc::Utf8ByteOffset{1}));
    EXPECT_FALSE(pc::is_codepoint_boundary(text, pc::Utf8ByteOffset{2}));
    EXPECT_FALSE(pc::is_codepoint_boundary(text, pc::Utf8ByteOffset{3}));
    EXPECT_TRUE(pc::is_codepoint_boundary(text, pc::Utf8ByteOffset{5}));   // 끝
    EXPECT_FALSE(pc::is_codepoint_boundary(text, pc::Utf8ByteOffset{6}));  // 범위 밖

    EXPECT_TRUE(pc::check_span(text, span(1, 4)));
    EXPECT_TRUE(pc::check_span(text, span(0, 5)));
    EXPECT_EQ(pc::check_span(text, span(2, 4)).error(), pc::InputError::NotCodepointBoundary);
    EXPECT_EQ(pc::check_span(text, span(1, 3)).error(), pc::InputError::NotCodepointBoundary);
    EXPECT_EQ(pc::check_span(text, span(4, 6)).error(), pc::InputError::OffsetOutOfRange);
}

TEST(CoreUtf8, OffsetConversion) {
    constexpr auto text = "a가b"sv;
    EXPECT_EQ(*pc::to_codepoint_offset(text, pc::Utf8ByteOffset{0}), pc::CodepointOffset{0});
    EXPECT_EQ(*pc::to_codepoint_offset(text, pc::Utf8ByteOffset{4}), pc::CodepointOffset{2});
    EXPECT_EQ(*pc::to_codepoint_offset(text, pc::Utf8ByteOffset{5}), pc::CodepointOffset{3});
    EXPECT_EQ(pc::to_codepoint_offset(text, pc::Utf8ByteOffset{2}).error(), pc::InputError::NotCodepointBoundary);
    EXPECT_EQ(pc::to_codepoint_offset(text, pc::Utf8ByteOffset{6}).error(), pc::InputError::OffsetOutOfRange);

    EXPECT_EQ(*pc::to_byte_offset(text, pc::CodepointOffset{1}), pc::Utf8ByteOffset{1});
    EXPECT_EQ(*pc::to_byte_offset(text, pc::CodepointOffset{2}), pc::Utf8ByteOffset{4});
    EXPECT_EQ(*pc::to_byte_offset(text, pc::CodepointOffset{3}), pc::Utf8ByteOffset{5});
    EXPECT_EQ(pc::to_byte_offset(text, pc::CodepointOffset{4}).error(), pc::InputError::OffsetOutOfRange);
    EXPECT_EQ(*pc::to_byte_offset(""sv, pc::CodepointOffset{0}), pc::Utf8ByteOffset{0});
}
