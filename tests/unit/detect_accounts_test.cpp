// 계좌번호: IBAN 전 국가, 외국 구조, 계좌 문맥 규칙과 그 예외. 국내 형식표는 detect_kr_accounts_test.cpp.
// 값은 모두 구조로 만든 합성 값이다.
#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

#include "../../src/detect/data/iban_registry.hpp"

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
using pc::EntityType;

namespace {

const pd::Detectors& detectors() {
    static const auto d = *pd::Detectors::make({});
    return d;
}

std::vector<std::string> accounts(std::string_view text) {
    std::vector<std::string> out;
    const auto entities = detectors().detect_segment(text, pc::SegmentIndex{0});
    EXPECT_TRUE(entities);
    for (const auto& e : *entities) {
        if (e.type() == EntityType::BankAccount) {
            out.emplace_back(text.substr(e.span().begin().value(), e.span().size()));
        }
    }
    return out;
}

bool has(const std::vector<std::string>& found, std::string_view value) {
    return std::ranges::find(found, std::string(value)) != found.end();
}

// SWIFT 구조 기호대로 채운 합성 IBAN(검증 자리 00, mod-97 은 맞지 않는다).
std::string synthetic_iban(const pd::data::IbanCountry& c) {
    std::string out(c.country);
    out += "00";
    for (std::size_t i = 0; i < c.bban.size();) {
        std::size_t count = 0;
        while (c.bban[i] >= '0' && c.bban[i] <= '9') {
            count = count * 10 + static_cast<std::size_t>(c.bban[i++] - '0');
        }
        if (c.bban[i] == '!') {
            ++i;
        }
        const char kind = c.bban[i++];
        out.append(count, kind == 'a' ? 'B' : '7');
    }
    return out;
}

}  // namespace

TEST(DetectAccounts, EveryIbanCountry) {
    for (const auto& c : pd::data::iban_countries) {
        const auto iban = synthetic_iban(c);
        ASSERT_EQ(iban.size(), c.length) << c.country;
        EXPECT_TRUE(has(accounts("송금처 " + iban + " 입니다"), iban)) << c.country;
        // 한 글자 모자라면 그 나라 구조가 아니다(문맥이 없으므로 문맥 규칙도 아님).
        const auto shorter = iban.substr(0, iban.size() - 1);
        EXPECT_FALSE(has(accounts("참고 " + shorter + " 끝"), shorter)) << c.country;
    }
    // 인쇄 형식(4자마다 공백)과 소문자.
    EXPECT_TRUE(has(accounts("DE00 7777 7777 7777 7777 77"), "DE00 7777 7777 7777 7777 77"));
    EXPECT_TRUE(has(accounts("de00777777777777777777"), "de00777777777777777777"));
}

TEST(DetectAccounts, ForeignStructures) {
    const std::vector<std::pair<std::string_view, std::string_view>> cases = {
        {"振込先 123-4567890", "123-4567890"},                       // 일본 지점-계좌
        {"記号番号 12345-12345678", "12345-12345678"},               // 일본 우체국 기호-번호
        {"sort code 12-34-56, account 12345678", "12-34-56"},       // 영국
        {"sort code 12-34-56, account 12345678", "12345678"},
        {"transit 12345-678 acct 1234567", "12345-678"},            // 캐나다
        {"BSB 062-000 number 12345678", "062-000"},                 // 호주
        {"routing 021000021 number 12345678", "021000021"},         // 미국 ABA
        {"routing 021000021 number 12345678", "12345678"},
        {"IFSC SBIN0001234 no 12345678901", "SBIN0001234"},          // 인도
        {"CLABE 002010077777777771", "002010077777777771"},         // 멕시코
        {"卡号 6212345678901234", "6212345678901234"},              // 중국
    };
    for (const auto& [text, value] : cases) {
        EXPECT_TRUE(has(accounts(text), value)) << text;
    }
    EXPECT_TRUE(accounts("참고 123456789 다음 12345678").empty());  // ABA 검증 자리 틀림(문맥어 없음)
    EXPECT_TRUE(accounts("참고 002010077777777772").empty());           // CLABE 검증 자리 틀림
}

TEST(DetectAccounts, ContextRule) {
    EXPECT_TRUE(has(accounts("입금 계좌 1234567890 으로"), "1234567890"));
    EXPECT_TRUE(has(accounts("account no. 98765432"), "98765432"));
    // 휴대폰 번호도 계좌 문맥이 있으면 계좌로 본다(ADR 0016 겹침 규칙).
    EXPECT_TRUE(has(accounts("환불 계좌: 010-2345-6789"), "010-2345-6789"));
    EXPECT_TRUE(accounts("연락처 010-2345-6789").empty());
    // 문맥 창 밖.
    EXPECT_TRUE(accounts("계좌는 나중에 알려 드리고 우선 주문 내역과 배송 일정을 다시 한번 정리해서 보내 주세요. 주문번호 1234567890").empty());
}

TEST(DetectAccounts, ContextRuleExceptions) {
    EXPECT_TRUE(accounts("계좌 이체 금액 1234567원").empty());
    EXPECT_TRUE(accounts("계좌 이체 금액 $ 1234567").empty());
    EXPECT_TRUE(accounts("입금일 2026-10-18 확인").empty());
    EXPECT_TRUE(accounts("입금 1,234,567 원").empty());
    EXPECT_TRUE(accounts("public 123456789").empty());   // "bic" 은 단어 일부라 문맥어가 아니다
    EXPECT_TRUE(accounts("참고 XX12 ABCD EFGH IJKL M").empty());  // IBAN 모양이지만 문맥 없음
    EXPECT_TRUE(has(accounts("IBAN XX12 ABCD EFGH IJKL M"), "XX12 ABCD EFGH IJKL M"));
}
