// 인코딩 덩어리: 종류별 찾기·풀기, 깊이 2, 깊이를 넘는 인코딩, 텍스트 아님, 256바이트 경계, core 판정 연결.
#include "prompt_airlock/detect/encoded.hpp"

#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
using pc::EncodingKind;
using pc::EntityType;

namespace {

std::vector<pc::EncodedFinding> findings(std::string_view text) {
    static const auto d = *pd::Detectors::make({});
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts));
    const auto document = *std::move(builder).build();
    return d.detect(document)->encoded;
}

pc::ReasonCode judged(std::string_view text) {
    const auto f = findings(text);
    const auto r = pc::judge_encoded(f);
    return r ? pc::ReasonCode::InternalError : r.error().code();
}

}  // namespace

TEST(DetectEncoded, EveryKindRevealsTheValue) {
    // 합성 주민번호 900101-1234567 과 합성 이메일을 여러 방식으로 감쌌다.
    const std::vector<std::pair<std::string_view, EncodingKind>> cases = {
        {"값 OTAwMTAxLTEyMzQ1Njc= 확인", EncodingKind::Base64},
        {"값 %39%30%30%31%30%31%2D%31%32%33%34%35%36%37 확인", EncodingKind::Percent},
        {"값 &#57;&#48;&#48;&#49;&#48;&#49;&#45;&#49;&#50;&#51;&#52;&#53;&#54;&#55; 확인", EncodingKind::HtmlNumericRef},
        {"값 \\u0039\\u0030\\u0030\\u0031\\u0030\\u0031\\u002d\\u0031\\u0032\\u0033\\u0034\\u0035\\u0036\\u0037 확인",
         EncodingKind::UnicodeEscape},
    };
    for (const auto& [text, kind] : cases) {
        const auto f = findings(text);
        ASSERT_EQ(f.size(), 1U) << text;
        EXPECT_EQ(f[0].kind, kind) << text;
        EXPECT_TRUE(f[0].decoded_is_text) << text;
        EXPECT_TRUE(f[0].targets.contains(EntityType::KoreanRrn)) << text;
        EXPECT_EQ(judged(text), pc::ReasonCode::EncodedTarget) << text;
    }
    const auto hex = findings("7573657231406578616d706c652e696e76616c6964");
    ASSERT_EQ(hex.size(), 1U);
    EXPECT_EQ(hex[0].kind, EncodingKind::Hex);
    EXPECT_TRUE(hex[0].targets.contains(EntityType::Email));
    // 대상이 없는 한국어 텍스트("가상 문서 본문입니다"의 base64)는 텍스트로 풀리고 대상이 없다.
    const auto plain = findings("6rCA7IOBIOusuOyEnCDrs7jrrLjsnoXri4jri6Q");
    ASSERT_EQ(plain.size(), 1U);
    EXPECT_TRUE(plain[0].decoded_is_text);
    EXPECT_TRUE(plain[0].targets.empty());
    const auto url = findings("a-b_cdefghijklmnop");
    ASSERT_EQ(url.size(), 1U);
    EXPECT_EQ(url[0].kind, EncodingKind::Base64Url);
}

TEST(DetectEncoded, DepthTwoAndBeyond) {
    const auto twice = findings("T1RBd01UQXhMVEV5TXpRMU5qYz0=");
    ASSERT_EQ(twice.size(), 1U);
    EXPECT_EQ(twice[0].depth.value(), 2);
    EXPECT_TRUE(twice[0].targets.contains(EntityType::KoreanRrn));
    EXPECT_FALSE(twice[0].still_encoded);
    // 세 번 감싸면 깊이 2 를 풀어도 여전히 인코딩이다(ADR 0017: 256바이트 이상이면 거절).
    const auto thrice = findings("WVVkV2MySkhPR2RrTWpsNVlrZFJaMk5IZUdoaFZ6Um5aRWRXTkdSQlBUMD0=");
    ASSERT_EQ(thrice.size(), 1U);
    EXPECT_TRUE(thrice[0].still_encoded);
}

TEST(DetectEncoded, OpaqueBlobBoundary) {
    // '/' 만으로 된 base64 는 0xFF 바이트로 풀려 텍스트가 아니다. 255자는 통과, 256자는 거절.
    EXPECT_EQ(judged(std::string(255, '/')), pc::ReasonCode::InternalError);
    EXPECT_EQ(judged(std::string(256, '/')), pc::ReasonCode::OpaqueEncodedBlob);
    // 짧은 일반 단어는 후보가 되어도 통과한다.
    EXPECT_EQ(judged("internationalization 은 긴 단어입니다"), pc::ReasonCode::InternalError);
}

TEST(DetectEncoded, DecodersRejectBrokenInput) {
    EXPECT_FALSE(pd::decode("abc", EncodingKind::Hex));
    EXPECT_FALSE(pd::decode("A", EncodingKind::Base64));
    EXPECT_FALSE(pd::decode("\\ud800\\u0041", EncodingKind::UnicodeEscape));  // 짝 없는 대리
    EXPECT_FALSE(pd::decode("&#1114112;&#65;", EncodingKind::HtmlNumericRef));  // U+10FFFF 초과
    EXPECT_EQ(*pd::decode("\\ud83d\\ude00", EncodingKind::UnicodeEscape), "\xF0\x9F\x98\x80");
    EXPECT_FALSE(pd::is_text(std::string("a\x01", 2)));
    EXPECT_TRUE(pd::is_text("가상\n"));
}
