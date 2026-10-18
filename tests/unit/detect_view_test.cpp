// 탐지용 보기: 정규화한 글자가 원문 위치를 잃지 않는지, 정규화 실패는 거절인지.
#include "prompt_airlock/detect/view.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace pd = prompt_airlock::detect;

namespace {

std::u32string chars(const pd::DetectionView& view) {
    std::u32string out;
    for (const auto& unit : view.units) {
        out.push_back(unit.value);
    }
    return out;
}

std::string_view original(std::string_view text, const pd::DetectionView& view, std::size_t i) {
    const auto span = view.units[i].source;
    return text.substr(span.begin().value(), span.size());
}

}  // namespace

TEST(DetectView, FullwidthBecomesAsciiAndKeepsSource) {
    const std::string text = "번호 ０１０－２３";
    const auto view = pd::make_view(text);
    ASSERT_TRUE(view);
    EXPECT_EQ(chars(*view), U"번호 010-23");
    EXPECT_EQ(original(text, *view, 3), "０");
    EXPECT_EQ(original(text, *view, 6), "－");
}

TEST(DetectView, ZeroWidthIsRemoved) {
    const std::string text = "0​1⁠﻿0";
    const auto view = pd::make_view(text);
    ASSERT_TRUE(view);
    EXPECT_EQ(chars(*view), U"010");
    EXPECT_EQ(original(text, *view, 2), "0");
}

TEST(DetectView, CompatibilityJamoComposeIntoSyllables) {
    // 호환 자모로 나눠 쓴 글자는 NFKC 뒤 음절로 합쳐진다. 합쳐진 글자는 두 자모 원문 전체를 가리킨다.
    const std::string text = "ㄱㅖㅈㅘ ㅋㅠ";
    const auto view = pd::make_view(text);
    ASSERT_TRUE(view);
    EXPECT_EQ(chars(*view), U"계좌 큐");
    EXPECT_EQ(original(text, *view, 0), "ㄱㅖ");
}

TEST(DetectView, ExpansionSharesSource) {
    // 하나가 여러 글자로 풀리면 모두 같은 원문을 가리킨다.
    const std::string text = "㈜가상";
    const auto view = pd::make_view(text);
    ASSERT_TRUE(view);
    EXPECT_EQ(chars(*view), U"(주)가상");
    EXPECT_EQ(original(text, *view, 0), "㈜");
    EXPECT_EQ(original(text, *view, 2), "㈜");
}

TEST(DetectView, InvalidUtf8IsUnavailable) {
    const auto view = pd::make_view("\xC0\x80");
    ASSERT_FALSE(view);
    EXPECT_EQ(view.error(), prompt_airlock::core::DetectError::Unavailable);
}
