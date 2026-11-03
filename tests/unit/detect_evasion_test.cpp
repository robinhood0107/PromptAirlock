// 우회 시험(Phase 5 계획 4.7 "막음" 행): 같은 합성 값을 바꿔 써도 같은 종류로 찾는다.
// 줄바꿈·보이지 않는 글자·LaTeX 표기로 나눈 번호는 막는다(#234, 결정 #235). PDF 가 줄 끝에서 번호를 끊기 때문이다.
// 막지 않는 우회(한글 숫자, 은어, 먼 문장, LaTeX 매크로로 따로 정의한 숫자)는 여기서 고정하지 않는다.
#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
using pc::EntityType;

namespace {

const pd::Detectors& detectors() {
    static const auto d = *pd::Detectors::make({});
    return d;
}

pc::EntityTypeSet detected(std::string_view text) {
    pc::EntityTypeSet types;
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts));
    const auto result = detectors().detect(*std::move(builder).build());
    EXPECT_TRUE(result);
    for (const auto& e : result->entities) {
        types.insert(e.type());
    }
    for (const auto& f : result->encoded) {
        types.merge(f.targets);
    }
    return types;
}

}  // namespace

TEST(DetectEvasion, BlockedRewritesAreStillFound) {
    const std::vector<std::pair<std::string_view, EntityType>> cases = {
        {"９００１０１－１２３４５６７", EntityType::KoreanRrn},                          // 전각
        {"9​0‌0‍1⁠0﻿1-1234567", EntityType::KoreanRrn},       // 보이지 않는 문자
        {"900101 1234567", EntityType::KoreanRrn},                                      // 공백 구분
        {"900101.1234567", EntityType::KoreanRrn},                                      // 점 구분
        {"900101–1234567", EntityType::KoreanRrn},                                 // en dash
        {"900101 - 1234567", EntityType::KoreanRrn},                                    // 구분자 여러 개
        {"계 좌 1234567890 으로", EntityType::BankAccount},                              // 단어 안 띄어쓰기
        {"ㄱㅖㅈㅘ 1234567890 으로", EntityType::BankAccount},                            // 자모 분리
        {"비 밀 번 호: Qwer1234", EntityType::Credential},
        {"참고 OTAwMTAxLTEyMzQ1Njc=", EntityType::KoreanRrn},                            // base64
        {"참고 %39%30%30%31%30%31%2D%31%32%33%34%35%36%37", EntityType::KoreanRrn},      // percent
        {"참고 T1RBd01UQXhMVEV5TXpRMU5qYz0=", EntityType::KoreanRrn},                    // base64 두 번
    };
    for (const auto& [text, type] : cases) {
        EXPECT_TRUE(detected(text).contains(type)) << pc::entity_type_name(type) << " " << text;
    }
}

// PDF·표에서 끊긴 번호와 이메일, 보이지 않는 글자, LaTeX 표기(#234).
TEST(DetectEvasion, SplitNumbersAndAddresses) {
    const std::vector<std::pair<std::string_view, EntityType>> cases = {
        {"900101-\n1234567", EntityType::KoreanRrn},              // 하이픈 뒤 줄바꿈
        {"900101\n-1234567", EntityType::KoreanRrn},              // 하이픈 앞 줄바꿈
        {"900101-\r\n1234567", EntityType::KoreanRrn},            // CRLF
        {"900101\t1234567", EntityType::KoreanRrn},               // 표의 앞뒤 칸
        {"900101-123\x1e" "4567", EntityType::KoreanRrn},         // 제어 문자
        {"900101-123\xEF\xBF\xBE" "4567", EntityType::KoreanRrn}, // U+FFFE
        {"900101-123\xC2\xAD" "4567", EntityType::KoreanRrn},     // soft hyphen
        {"900101-123\xE2\x81\xA3" "4567", EntityType::KoreanRrn}, // U+2063
        {"900101-123\xE1\xA0\x8E" "4567", EntityType::KoreanRrn}, // U+180E
        {"900101-123\xEF\xB8\x8E" "4567", EntityType::KoreanRrn}, // 변이 선택자 U+FE0E(기본 무시 문자)
        {"$900101\\text{-}1234567$", EntityType::KoreanRrn},      // LaTeX
        {"900101{-}1234567", EntityType::KoreanRrn},
        {"900101\\,-\\,1234567", EntityType::KoreanRrn},
        {"\\item 900101-123% 주석\n  4567", EntityType::KoreanRrn},  // LaTeX 주석이 줄을 이음
        {"번호 900101#sym.dash1234567", EntityType::KoreanRrn},  // Typst 기호
        {"번호 900101#[-]1234567", EntityType::KoreanRrn},        // Typst 내용 묶음
        {"010-2345-\n6789", EntityType::KoreanPhone},
        {"4111-1111-\n1111-1111", EntityType::CardNumber},
        {"hong.gildong@\nexample.com", EntityType::Email},
        {"hong.gildong@example.\ncom", EntityType::Email},
        {"hong.\ngildong@example.com", EntityType::Email},
    };
    for (const auto& [text, type] : cases) {
        EXPECT_TRUE(detected(text).contains(type)) << pc::entity_type_name(type) << " " << text;
    }
}

TEST(DetectEvasion, SplitNumbersKeepSpansAndLimits) {
    const auto spans = [](std::string_view text) {
        std::vector<std::string_view> out;
        const auto found = detectors().detect_segment(text, pc::SegmentIndex{0});  // 임시 expected 를 범위 for 에 바로 쓰면 먼저 사라진다
        EXPECT_TRUE(found);
        for (const auto& e : *found) {
            out.push_back(text.substr(e.span().begin().value(), e.span().size()));
        }
        return out;
    };
    // 치환 구간은 LaTeX 명령까지 덮는다.
    EXPECT_EQ(spans("번호 $900101\\text{-}1234567$ 끝"), std::vector<std::string_view>{"900101\\text{-}1234567"});
    // 한계: 탐지 보기는 매크로를 펼치지 않는다. LaTeX·Typst 문서 파일의 매크로는 추출 단계 pandoc 이 맡는다(결정 #238).
    EXPECT_FALSE(detected("\\newcommand{\\front}{900101}\n번호 \\front-1234567").contains(EntityType::KoreanRrn));
    // 보이는 서식 문자(아랍 숫자 기호 U+0600)는 기본 무시 문자가 아니라 지우지 않는다.
    EXPECT_FALSE(detected("900101-123\xD8\x80" "4567").contains(EntityType::KoreanRrn));
    EXPECT_EQ(spans("hong.gildong@\nexample.com 으로"), std::vector<std::string_view>{"hong.gildong@\nexample.com"});
    // 빈 줄을 넘거나 줄바꿈이 두 번이면 잇지 않는다(표의 다른 줄).
    EXPECT_FALSE(detected("900101-\n\n1234567").contains(EntityType::KoreanRrn));
    // 하이픈 없는 숫자는 줄을 넘어 잇지 않는다(표에서 줄마다 놓인 날짜).
    EXPECT_TRUE(detected("25.10.21\n26.03.07\n25.11.04").empty());
    EXPECT_FALSE(detected("900101\n1234567").contains(EntityType::KoreanRrn));
    EXPECT_TRUE(detected("1-1\n1-2\n1-3\n1-4\n1-5\n1-6\n1-7").empty());
    // 숫자 사이에서 줄이 끊긴 번호는 단서 낱말 뒤에서만 잇는다(결정 #238).
    EXPECT_FALSE(detected("900101-123\n4567").contains(EntityType::KoreanRrn));
    EXPECT_TRUE(detected("주민등록번호 900101-123\n4567").contains(EntityType::KoreanRrn));
    EXPECT_TRUE(detected("주민번호: 900101\n1234567").contains(EntityType::KoreanRrn));
    EXPECT_TRUE(detected("휴대폰 010 2345\n6789").contains(EntityType::KoreanPhone));
    EXPECT_TRUE(detected("Card 4111 1111 1111\n1111").contains(EntityType::CardNumber));
    EXPECT_TRUE(detected("사업자등록번호 220-81-\n62517").contains(EntityType::KoreanBusinessNo));
    // 단서가 있어도 표의 날짜는 번호가 되지 않는다(날짜 모양은 주민번호 구조를 못 맞춤).
    EXPECT_FALSE(detected("주민센터 일정\n25.10.21\n26.03.07").contains(EntityType::KoreanRrn));
    // 주소 끝 마침표 뒤 줄바꿈은 다음 줄 낱말로 넘어가도 주소는 그대로 찾는다.
    EXPECT_TRUE(detected("메일 hong@example.com\n2024년").contains(EntityType::Email));
    // 기간 표시 ~ 는 날짜를 번호로 잇지 않는다.
    EXPECT_TRUE(detected("2025. 10. 21 ~ 2026. 3. 7 {공고}").empty());
    // 금액의 $ 는 LaTeX 보기에서도 계좌로 보지 않는다.
    EXPECT_FALSE(detected("계좌 이체 금액 $ 1234567").contains(EntityType::BankAccount));
}
