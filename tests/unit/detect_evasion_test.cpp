// 우회 시험(Phase 5 계획 4.7 "막음" 행): 같은 합성 값을 바꿔 써도 같은 종류로 찾는다.
// 막지 않는 우회(줄바꿈으로 나눈 숫자, 한글 숫자, 은어, 먼 문장)는 Phase 7.5 대상이라 여기서 고정하지 않는다.
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
