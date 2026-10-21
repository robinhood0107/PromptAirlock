#include "prompt_airlock/core/particle.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace pc = prompt_airlock::core;

namespace {

// 텍스트 전체를 이름 하나로 탐지했다고 보고 조사를 뗀 결과를 돌려준다. 이름은 합성 음절이다.
std::string trim(const std::string& text) {
    const auto units = pc::decode_utf8(text);
    const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{0}, pc::Utf8ByteOffset{text.size()});
    const auto out = pc::trim_trailing_particles(*units, span);
    return text.substr(out.begin().value(), out.size());
}

}  // namespace

TEST(CoreParticle, StripsWhenBatchimAgrees) {
    EXPECT_EQ(trim("나라비는"), "나라비");      // 받침 없음 + 는
    EXPECT_EQ(trim("가상인을"), "가상인");      // 받침 있음 + 을
    EXPECT_EQ(trim("다온별에게"), "다온별");
    EXPECT_EQ(trim("가상인이랑"), "가상인");
    EXPECT_EQ(trim("하늬솔님"), "하늬솔");
    EXPECT_EQ(trim("누리별테크가"), "누리별테크");
    EXPECT_EQ(trim("가온해운과"), "가온해운");
    EXPECT_EQ(trim("누리별테크에"), "누리별테크");
    EXPECT_EQ(trim("Minsu Kim는"), "Minsu Kim");  // 영문 뒤는 받침을 가릴 수 없어 짝 조사 둘 다 뗀다
    EXPECT_EQ(trim("Yejun Kwon를"), "Yejun Kwon");
    EXPECT_EQ(trim("Lee가"), "Lee");
    EXPECT_EQ(trim("제윤호한테서"), "제윤호");
    EXPECT_EQ(trim("가온해운으로부터"), "가온해운");
    EXPECT_EQ(trim("김하나"), "김하나");  // 짝 없는 '나' 도 3음절 이상 남을 때만
    EXPECT_EQ(trim("견하랑"), "견하랑");  // 이름 끝 '랑' 은 조사로 떼지 않는다(세 글자 이상 남을 때만)
    EXPECT_EQ(trim("견하랑과"), "견하랑");
    EXPECT_EQ(trim("김민수랑"), "김민수");  // NER 구간을 어절까지 넓힌 뒤 붙어 오는 장소 조사
}

TEST(CoreParticle, KeepsNameWhenAgreementFails) {
    EXPECT_EQ(trim("다하은"), "다하은");        // 앞 음절 '하' 에 받침이 없어 '은' 은 조사가 아니다
    EXPECT_EQ(trim("다하은은"), "다하은");
    EXPECT_EQ(trim("모가은이"), "모가은");
    EXPECT_EQ(trim("다현도"), "다현도");        // 짝 없는 '도' 는 3음절 이상 남을 때만
    EXPECT_EQ(trim("라온비도"), "라온비");
    EXPECT_EQ(trim("가온에"), "가온에");        // 짝 없는 '에' 도 3음절 이상 남을 때만
    EXPECT_EQ(trim("가나"), "가나");
}

TEST(CoreParticle, UsesSourceBytesOfDetectionView) {
    // 탐지용 보기에서는 합성된 음절 하나가 원문 여러 byte(예: 조합형 자모)를 덮는다.
    const std::vector<char32_t> composed{U'가', U'상', U'늘', U'을'};
    std::vector<pc::DecodedCodepoint> units;
    for (std::size_t i = 0; i < composed.size(); ++i) {
        units.push_back({composed[i], *pc::ByteSpan::make(pc::Utf8ByteOffset{i * 9}, pc::Utf8ByteOffset{i * 9 + 9})});
    }
    const auto whole = *pc::ByteSpan::make(pc::Utf8ByteOffset{0}, pc::Utf8ByteOffset{36});
    EXPECT_EQ(pc::trim_trailing_particles(units, whole).end().value(), 27U);
}

TEST(CoreParticle, OnlyLooksInsideSpan) {
    const std::string text = "회의에 가상인은 참석";
    const auto units = pc::decode_utf8(text);
    const auto begin = text.find("가상인은");
    const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{begin + 12});
    const auto out = pc::trim_trailing_particles(*units, span);
    EXPECT_EQ(text.substr(out.begin().value(), out.size()), "가상인");
}
