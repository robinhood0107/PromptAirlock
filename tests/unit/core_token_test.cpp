#include "prompt_airlock/core/token.hpp"

#include <gtest/gtest.h>

#include <string>
#include <type_traits>

namespace pc = prompt_airlock::core;
using namespace std::string_literals;

static_assert(!std::is_constructible_v<pc::Token, std::string, pc::EntityType>);

namespace {

// 합성 token. R 은 Crockford base32 대문자 10자.
const std::string person = "\xE2\x9F\xA6PERSON_7Q2MK4XD9A\xE2\x9F\xA7";
const std::string email = "\xE2\x9F\xA6" "EMAIL_0123456789\xE2\x9F\xA7";

}  // namespace

TEST(CoreToken, LabelsOnlyForTokenizeTypes) {
    EXPECT_EQ(pc::token_label(pc::EntityType::Person), "PERSON");
    EXPECT_EQ(pc::token_label(pc::EntityType::KoreanBusinessNo), "KOREAN_BUSINESS_NO");
    EXPECT_FALSE(pc::token_label(pc::EntityType::KoreanRrn));
    for (const auto type : pc::all_entity_types()) {
        if (const auto label = pc::token_label(type)) {
            EXPECT_LE(label->size(), 24U);
        }
    }
}

TEST(CoreToken, ParsesExactShape) {
    const auto token = pc::parse_token(person);
    ASSERT_TRUE(token);
    EXPECT_EQ(token->text(), person);
    EXPECT_EQ(token->label_type(), pc::EntityType::Person);
    EXPECT_EQ(token->random_part(), "7Q2MK4XD9A");
}

TEST(CoreToken, RejectsEveryVariant) {
    const std::string variants[] = {
        "\xE2\x9F\xA6person_7q2mk4xd9a\xE2\x9F\xA7",    // 소문자화
        "\xE2\x9F\xA6PERSON_7Q2MK 4XD9A\xE2\x9F\xA7",   // 공백 삽입
        "PERSON_7Q2MK4XD9A",                             // 괄호 제거
        "[PERSON_7Q2MK4XD9A]",                           // ASCII 괄호
        "\xE2\x9F\xA6PERSON_7Q2MK4XD9I\xE2\x9F\xA7",    // 쓰지 않는 문자 I
        "\xE2\x9F\xA6PERSONA_7Q2MK4XD9A\xE2\x9F\xA7",   // 라벨 변경
        "\xE2\x9F\xA6KOREAN_RRN_7Q2MK4XD9A\xE2\x9F\xA7",  // 차단 종류 라벨
        "\xE2\x9F\xA6PERSON_7Q2MK4XD9\xE2\x9F\xA7",     // 9자
        "\xE2\x9F\xA6PERSON_7Q2MK4XD9AB\xE2\x9F\xA7",   // 11자
        "\xE2\x9F\xA6PERSON7Q2MK4XD9A\xE2\x9F\xA7",     // 밑줄 없음
        person + " ",                                    // 뒤에 공백
    };
    for (const auto& variant : variants) {
        EXPECT_EQ(pc::parse_token(variant).error(), pc::ProtectionError::MalformedToken) << variant;
    }
}

TEST(CoreToken, ScanFindsExactTokensWithByteSpans) {
    const std::string text = "가상 " + person + "님께 " + email + email + " 끝";
    const auto found = pc::scan_tokens(text);
    ASSERT_EQ(found.size(), 3U);
    EXPECT_EQ(found[0].span.begin().value(), "가상 "s.size());
    EXPECT_EQ(found[0].span.size(), person.size());
    EXPECT_EQ(found[0].token.label_type(), pc::EntityType::Person);
    EXPECT_EQ(found[1].span.end(), found[2].span.begin());  // 붙어 있어도 따로 찾는다
    EXPECT_EQ(found[2].token.text(), email);
}

TEST(CoreToken, ScanSkipsMalformedAndNestedCandidates) {
    const std::string text = "\xE2\x9F\xA6person_7q2mk4xd9a\xE2\x9F\xA7 \xE2\x9F\xA6" + person + " \xE2\x9F\xA6";
    const auto found = pc::scan_tokens(text);
    ASSERT_EQ(found.size(), 1U);
    EXPECT_EQ(found[0].token.text(), person);
    EXPECT_TRUE(pc::scan_tokens("").empty());
    EXPECT_TRUE(pc::scan_tokens("\xE2\x9F\xA6").empty());
}
