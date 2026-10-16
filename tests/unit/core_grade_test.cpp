#include "prompt_airlock/core/grade.hpp"

#include <gtest/gtest.h>

#include <string_view>
#include <type_traits>
#include <vector>

namespace pc = prompt_airlock::core;
using pc::GradePolicy;
using pc::ReasonCode;

// 증표는 resolve_grade 를 거쳐야만 생긴다.
static_assert(!std::is_default_constructible_v<pc::OpenGrade>);
static_assert(!std::is_constructible_v<pc::OpenGrade, pc::GradeOrigin>);
static_assert(!std::is_default_constructible_v<pc::detail::StateKey<pc::OpenGrade>>);

namespace {

ReasonCode reject(GradePolicy policy, std::vector<std::string_view> marks) {
    const auto grade = pc::resolve_grade(policy, marks);
    return grade ? ReasonCode::InternalError : grade.error().code();
}

}  // namespace

TEST(CoreGrade, ParsesExactMarksOnly) {
    EXPECT_EQ(*pc::parse_grade_mark("C"), pc::DataGrade::Classified);
    EXPECT_EQ(*pc::parse_grade_mark("S"), pc::DataGrade::Sensitive);
    EXPECT_EQ(*pc::parse_grade_mark("O"), pc::DataGrade::Open);
    for (const std::string_view bad : {"o", "", "O ", " O", "X", "O,S", "OPEN"}) {
        EXPECT_FALSE(pc::parse_grade_mark(bad)) << bad;
    }
}

TEST(CoreGrade, OOnlyDefaultsToOpenWithoutMark) {
    const auto grade = pc::resolve_grade(GradePolicy::OOnly, {});
    ASSERT_TRUE(grade);
    EXPECT_EQ(grade->origin(), pc::GradeOrigin::SourceDefault);
}

TEST(CoreGrade, DeclareRequiresMark) { EXPECT_EQ(reject(GradePolicy::Declare, {}), ReasonCode::GradeUnresolved); }

TEST(CoreGrade, OpenMarkAcceptedUnderBothPolicies) {
    for (const auto policy : {GradePolicy::OOnly, GradePolicy::Declare}) {
        const std::vector<std::string_view> marks{"O"};
        const auto grade = pc::resolve_grade(policy, marks);
        ASSERT_TRUE(grade);
        EXPECT_EQ(grade->origin(), pc::GradeOrigin::Header);
    }
}

TEST(CoreGrade, ClassifiedAndSensitiveRejected) {
    for (const auto policy : {GradePolicy::OOnly, GradePolicy::Declare}) {
        EXPECT_EQ(reject(policy, {"C"}), ReasonCode::GradeClassified);
        EXPECT_EQ(reject(policy, {"S"}), ReasonCode::GradeSensitive);
    }
}

TEST(CoreGrade, MultipleOrMalformedMarksUnresolved) {
    for (const auto policy : {GradePolicy::OOnly, GradePolicy::Declare}) {
        EXPECT_EQ(reject(policy, {"O", "O"}), ReasonCode::GradeUnresolved);
        EXPECT_EQ(reject(policy, {"O", "S"}), ReasonCode::GradeUnresolved);
        EXPECT_EQ(reject(policy, {"o"}), ReasonCode::GradeUnresolved);
        EXPECT_EQ(reject(policy, {"O,S"}), ReasonCode::GradeUnresolved);
        EXPECT_EQ(reject(policy, {""}), ReasonCode::GradeUnresolved);
    }
}
