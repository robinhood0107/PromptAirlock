#include <gtest/gtest.h>

#include "decode.hpp"

using namespace prompt_airlock::ner;

namespace {

// 원문 전체를 하나의 entity 로 본다고 가정하고 후처리 결과 문자열을 돌려준다.
std::string strip(const std::string& text, std::size_t entity_bytes, EntityType type = EntityType::Person) {
  auto n = normalize(text, {});
  EXPECT_TRUE(n);
  const EntitySpan e{type, ByteSpan{Utf8ByteOffset{0}, Utf8ByteOffset{entity_bytes}}};
  const auto out = strip_trailing_particles(std::span(&e, 1), *n);
  return text.substr(0, out.front().bytes.end.value);
}

std::string s(const char8_t* u) { return std::string(reinterpret_cast<const char*>(u)); }

}  // namespace

TEST(Labels, ParsesPrefixAndSuffixForms) {
  const auto t = build_label_table({"O", "B-NAME", "I-NAME", "S-ORGANIZATION", "PER-B", "B-PHONE"},
                                   {{"NAME", EntityType::Person}, {"ORGANIZATION", EntityType::Organization},
                                    {"PER", EntityType::Person}});
  EXPECT_FALSE(t[0].type);
  EXPECT_EQ(t[1].prefix, 'B');
  EXPECT_EQ(*t[2].type, EntityType::Person);
  EXPECT_EQ(t[3].prefix, 'S');
  EXPECT_EQ(*t[3].type, EntityType::Organization);
  EXPECT_EQ(t[4].prefix, 'B');
  EXPECT_FALSE(t[5].type);  // 관심 밖 label 은 O 로 취급
}

TEST(Decode, BioAndBioesSpansMapToOriginalBytes) {
  const std::string text = "AB CD";
  const std::vector<Token> toks = {{2, {}, true},
                                   {10, {Utf8ByteOffset{0}, Utf8ByteOffset{1}}, false},
                                   {11, {Utf8ByteOffset{1}, Utf8ByteOffset{2}}, false},
                                   {12, {Utf8ByteOffset{3}, Utf8ByteOffset{5}}, false},
                                   {3, {}, true}};
  const auto labels = build_label_table({"O", "B-NAME", "I-NAME", "S-ORG"},
                                        {{"NAME", EntityType::Person}, {"ORG", EntityType::Organization}});
  Logits l{5, 4, std::vector<float>(20, 0.f)};
  auto set = [&](std::size_t pos, std::size_t lab) { l.data[pos * 4 + lab] = 1.f; };
  set(0, 0); set(1, 1); set(2, 2); set(3, 3); set(4, 0);
  const auto out = decode_entities(toks, l, labels, text, {});
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0], (EntitySpan{EntityType::Person, {Utf8ByteOffset{0}, Utf8ByteOffset{2}}}));
  EXPECT_EQ(out[1], (EntitySpan{EntityType::Organization, {Utf8ByteOffset{3}, Utf8ByteOffset{5}}}));
}

TEST(Particles, StripsOnlyWhenBatchimAgreementHolds) {
  EXPECT_EQ(strip(s(u8"김민수는"), s(u8"김민수는").size()), s(u8"김민수"));
  EXPECT_EQ(strip(s(u8"박서준을"), s(u8"박서준을").size()), s(u8"박서준"));
  EXPECT_EQ(strip(s(u8"강도윤에게"), s(u8"강도윤에게").size()), s(u8"강도윤"));
  EXPECT_EQ(strip(s(u8"윤서연이랑"), s(u8"윤서연이랑").size()), s(u8"윤서연"));
  EXPECT_EQ(strip(s(u8"오태호님"), s(u8"오태호님").size()), s(u8"오태호"));
  // 이름 끝 음절이 조사와 같은 경우는 받침 호응이 맞지 않아 유지된다.
  EXPECT_EQ(strip(s(u8"김하은"), s(u8"김하은").size()), s(u8"김하은"));
  EXPECT_EQ(strip(s(u8"김하은은"), s(u8"김하은은").size()), s(u8"김하은"));
  EXPECT_EQ(strip(s(u8"이가은이"), s(u8"이가은이").size()), s(u8"이가은"));
  // 짝 없는 한 음절 조사는 3음절 이상 남을 때만 자른다.
  EXPECT_EQ(strip(s(u8"김현도"), s(u8"김현도").size()), s(u8"김현도"));
  EXPECT_EQ(strip(s(u8"권나래도"), s(u8"권나래도").size()), s(u8"권나래"));
  EXPECT_EQ(strip(s(u8"누리별테크가"), s(u8"누리별테크가").size(), EntityType::Organization), s(u8"누리별테크"));
  EXPECT_EQ(strip(s(u8"가온해운과"), s(u8"가온해운과").size(), EntityType::Organization), s(u8"가온해운"));
}

TEST(Particles, WorksOnNfdOriginalAndKeepsSyllableBoundary) {
  const std::string nfd = std::string("\xE1\x84\x8C\xE1\x85\xA5\xE1\x86\xBC") +  // 정
                          "\xE1\x84\x92\xE1\x85\xA1" +                           // 하
                          "\xE1\x84\x82\xE1\x85\xB3\xE1\x86\xAF" +               // 늘
                          "\xE1\x84\x8B\xE1\x85\xB3\xE1\x86\xAF";                // 을
  EXPECT_EQ(strip(nfd, nfd.size()).size(), nfd.size() - 9);
}
