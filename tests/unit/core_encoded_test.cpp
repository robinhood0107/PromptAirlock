#include "prompt_airlock/core/encoded.hpp"

#include <gtest/gtest.h>

#include <vector>

namespace pc = prompt_airlock::core;
using pc::ReasonCode;

namespace {

pc::EncodedFinding finding(std::size_t length, bool is_text, bool still_encoded, pc::EntityTypeSet targets = {}) {
    return pc::EncodedFinding{pc::SegmentIndex{0},
                              *pc::ByteSpan::make(pc::Utf8ByteOffset{10}, pc::Utf8ByteOffset{10 + length}),
                              pc::EncodingKind::Base64,
                              *pc::DecodeDepth::make(1),
                              is_text,
                              still_encoded,
                              targets};
}

ReasonCode judge(std::vector<pc::EncodedFinding> findings) {
    const auto result = pc::judge_encoded(findings);
    return result ? ReasonCode::InternalError : result.error().code();
}

}  // namespace

TEST(CoreEncoded, DepthIsOneOrTwo) {
    EXPECT_FALSE(pc::DecodeDepth::make(0));
    EXPECT_EQ(pc::DecodeDepth::make(2)->value(), 2);
    EXPECT_FALSE(pc::DecodeDepth::make(3));
}

TEST(CoreEncoded, TargetInsideBlobRejectsAtAnyLength) {
    pc::EntityTypeSet rrn;
    rrn.insert(pc::EntityType::KoreanRrn);
    EXPECT_EQ(judge({finding(16, true, false, rrn)}), ReasonCode::EncodedTarget);

    pc::EntityTypeSet email;
    email.insert(pc::EntityType::Email);  // 가명화 종류도 인코딩 안이면 거절
    const auto result = pc::judge_encoded(std::vector{finding(20, true, false, email)});
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code(), ReasonCode::EncodedTarget);
    EXPECT_TRUE(result.error().for_user().blocked_types.empty());  // 사용자에게는 코드만
    EXPECT_EQ(std::get<pc::EncodedLocation>(result.error().for_audit().findings.front()).kind,
              pc::EncodingKind::Base64);
}

TEST(CoreEncoded, OpaqueBlobBoundaryAt256Bytes) {
    EXPECT_TRUE(pc::judge_encoded(std::vector{finding(255, false, false)}));
    EXPECT_EQ(judge({finding(256, false, false)}), ReasonCode::OpaqueEncodedBlob);
    // 깊이 2 를 풀어도 인코딩이면 텍스트가 아닌 것과 같이 본다(#45).
    EXPECT_TRUE(pc::judge_encoded(std::vector{finding(255, true, true)}));
    EXPECT_EQ(judge({finding(256, true, true)}), ReasonCode::OpaqueEncodedBlob);
    // 확인된 텍스트는 길어도 통과한다.
    EXPECT_TRUE(pc::judge_encoded(std::vector{finding(4096, true, false)}));
}

TEST(CoreEncoded, TargetReasonWinsOverOpaque) {
    pc::EntityTypeSet card;
    card.insert(pc::EntityType::CardNumber);
    EXPECT_EQ(judge({finding(300, false, false), finding(20, true, false, card)}), ReasonCode::EncodedTarget);
    EXPECT_TRUE(pc::judge_encoded(std::vector<pc::EncodedFinding>{}));
}
