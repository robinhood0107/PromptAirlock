// 숫자 묶음과 단어 일치기.
#include "prompt_airlock/detect/scan.hpp"
#include "prompt_airlock/detect/terms.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace pd = prompt_airlock::detect;

namespace {

std::vector<std::vector<std::string>> runs(std::string_view text) {
    std::vector<std::vector<std::string>> out;
    for (const auto& run : pd::digit_runs(*pd::make_view(text))) {
        auto& groups = out.emplace_back();
        for (const auto& group : run.groups) {
            groups.push_back(group.digits);
        }
    }
    return out;
}

}  // namespace

TEST(DetectScan, DigitRuns) {
    using Runs = std::vector<std::vector<std::string>>;
    EXPECT_EQ(runs("010-2345-6789"), (Runs{{"010", "2345", "6789"}}));
    EXPECT_EQ(runs("123 - 456"), (Runs{{"123", "456"}}));
    EXPECT_EQ(runs("12    34"), (Runs{{"12"}, {"34"}}));         // 구분자 4개 이상이면 끊는다
    EXPECT_EQ(runs("1,234,567원"), (Runs{{"1"}, {"234"}, {"567"}}));  // 쉼표는 구분자가 아니다
    EXPECT_EQ(runs("A123456 99x"), (Runs{}));                       // 영문에 붙은 숫자는 후보가 아니다
    EXPECT_EQ(runs("1.2"), (Runs{{"1", "2"}}));
    EXPECT_EQ(runs("번호123번"), (Runs{{"123"}}));                  // 한글은 경계다
}

TEST(DetectScan, TermMatcher) {
    const std::vector<std::u32string_view> terms = {U"가상기관", U"기관", U"acme"};
    const auto matcher = pd::TermMatcher::make(terms);
    const auto view = *pd::make_view("가상 기관 ACME");
    std::vector<std::uint32_t> found;
    for (const auto& hit : matcher.find(view)) {
        found.push_back(hit.term);
    }
    std::ranges::sort(found);
    EXPECT_EQ(found, (std::vector<std::uint32_t>{0, 1, 2}));
    EXPECT_TRUE(pd::TermMatcher::make({}).find(view).empty());
}
