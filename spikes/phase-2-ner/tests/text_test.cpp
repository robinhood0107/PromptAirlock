#include <gtest/gtest.h>

#include <filesystem>
#include <set>

#include "fixtures.hpp"
#include "text.hpp"

using namespace prompt_airlock::ner;

namespace {
std::filesystem::path fixture_path() { return std::filesystem::path(PA_FIXTURE_DIR) / "ner.jsonl"; }
}  // namespace

TEST(Utf8, RejectsMalformedInput) {
  EXPECT_FALSE(decode_utf8("\xC0\x80").has_value());          // overlong
  EXPECT_FALSE(decode_utf8("\xED\xA0\x80").has_value());      // surrogate
  EXPECT_FALSE(decode_utf8("\xEA\xB9").has_value());          // 잘린 시퀀스
  EXPECT_FALSE(decode_utf8("\xF5\x80\x80\x80").has_value());  // 범위 초과
  EXPECT_FALSE(normalize("김\xFF", {}).has_value());           // 정규화도 fail-closed
}

TEST(Normalize, NfdHangulMapsBackToWholeOriginalSyllable) {
  // "김" NFD = U+1100 U+1175 U+11B7 (9 bytes)
  const std::string nfd = "\xE1\x84\x80\xE1\x85\xB5\xE1\x86\xB7";
  auto n = normalize(nfd + "a", {});
  ASSERT_TRUE(n);
  ASSERT_EQ(n->size(), 2u);
  EXPECT_EQ((*n)[0].cp, U'김');
  EXPECT_EQ((*n)[0].src, (ByteSpan{Utf8ByteOffset{0}, Utf8ByteOffset{9}}));
  EXPECT_EQ((*n)[1].src, (ByteSpan{Utf8ByteOffset{9}, Utf8ByteOffset{10}}));
}

TEST(Normalize, CombiningMarkComposesAndKeepsBothBytes) {
  auto n = normalize("e\xCC\x81x", {});  // e + U+0301
  ASSERT_TRUE(n);
  ASSERT_EQ(n->size(), 2u);
  EXPECT_EQ((*n)[0].cp, U'é');
  EXPECT_EQ((*n)[0].src, (ByteSpan{Utf8ByteOffset{0}, Utf8ByteOffset{3}}));
}

TEST(Normalize, ZeroWidthIsDroppedButOriginalRangeIsPreservedAround) {
  auto n = normalize("김​민", {});
  ASSERT_TRUE(n);
  ASSERT_EQ(n->size(), 2u);
  EXPECT_EQ((*n)[1].src.begin.value, 6u);  // 김(3) + ZWSP(3)
  auto kept = normalize("김​민", NormPolicy{true, false});
  ASSERT_TRUE(kept);
  EXPECT_EQ(kept->size(), 3u);
}

TEST(Normalize, FullwidthIsNotFoldedByNfc) {
  auto n = normalize("ＡＢＣ", {});
  ASSERT_TRUE(n);
  EXPECT_EQ((*n)[0].cp, U'Ａ');  // NFKC 가 아니므로 유지
}

TEST(Normalize, EmojiKeepsFourByteSpan) {
  auto n = normalize("👍a", {});
  ASSERT_TRUE(n);
  EXPECT_EQ((*n)[0].src, (ByteSpan{Utf8ByteOffset{0}, Utf8ByteOffset{4}}));
  EXPECT_EQ(to_codepoint_offset("👍a", Utf8ByteOffset{4}).value, 1u);
  EXPECT_FALSE(is_codepoint_boundary("👍a", Utf8ByteOffset{2}));
}

TEST(Fixtures, OffsetsAreConsistentAndCoverageIsComplete) {
  auto fx = load_fixtures(fixture_path());
  ASSERT_TRUE(fx) << fx.error();
  EXPECT_GE(fx->size(), 40u);
  std::set<std::string> cats;
  std::set<std::string> ids;
  for (const auto& f : *fx) {
    cats.insert(f.category);
    EXPECT_TRUE(ids.insert(f.id).second) << f.id;
    EXPECT_TRUE(decode_utf8(f.text).has_value()) << f.id;
    for (const auto& e : f.entities) {
      ASSERT_LE(e.bytes.end.value, f.text.size()) << f.id;
      EXPECT_EQ(f.text.substr(e.bytes.begin.value, e.bytes.size()), e.text) << f.id;
      EXPECT_EQ(to_codepoint_offset(f.text, e.bytes.begin), e.start_cp) << f.id;
      EXPECT_EQ(to_codepoint_offset(f.text, e.bytes.end), e.end_cp) << f.id;
      EXPECT_TRUE(is_codepoint_boundary(f.text, e.bytes.begin)) << f.id;
      EXPECT_TRUE(is_codepoint_boundary(f.text, e.bytes.end)) << f.id;
    }
  }
  for (const char* c : {"name", "two_people", "repeat", "person_org", "particle", "hangul_ascii", "punctuation",
                        "normalization", "negative", "long"})
    EXPECT_TRUE(cats.contains(c)) << c;
}
