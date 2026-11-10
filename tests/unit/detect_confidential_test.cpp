// 기밀 문장(ADR 0027): 기밀 표지어 + 업종·기관 대상어가 같은 문장이나 이웃 문장에 있을 때만 차단. 문장은 합성이다.
#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;

namespace {

pd::Detectors make(std::vector<pd::Industry> industries, std::vector<std::string> markers = {},
                   std::vector<std::string> subjects = {}) {
    pd::InstitutionPolicy policy;
    policy.industries = std::move(industries);
    policy.confidential_markers = std::move(markers);
    policy.confidential_subjects = std::move(subjects);
    return *pd::Detectors::make({}, {}, policy);
}

std::vector<std::string> blocked(const pd::Detectors& d, std::string_view text) {
    std::vector<std::string> out;
    const auto entities = d.detect_segment(text, pc::SegmentIndex{0});
    EXPECT_TRUE(entities);
    for (const auto& e : *entities) {
        if (e.type() == pc::EntityType::ConfidentialMatter) {
            out.emplace_back(text.substr(e.span().begin().value(), e.span().size()));
        }
    }
    return out;
}

}  // namespace

TEST(DetectConfidential, MarkerAndSubjectInOneSentence) {
    const auto bank = make({pd::Industry::Bank});
    EXPECT_EQ(blocked(bank, "대외비인 3분기 잠정 실적 자료를 요약해 줘."),
              std::vector<std::string>{"대외비인 3분기 잠정 실적 자료를 요약해 줘."});
    EXPECT_EQ(blocked(bank, "Confidential: 인수합병 검토 메모 정리"),
              std::vector<std::string>{"Confidential: 인수합병 검토 메모 정리"});
    const auto city = make({pd::Industry::PublicAdmin});
    EXPECT_EQ(blocked(city, "다음은 내부 검토용 예산 편성안입니다. 표로 바꿔 주세요."),
              std::vector<std::string>{"다음은 내부 검토용 예산 편성안입니다."});
}

TEST(DetectConfidential, NeighbourSentencesAreBlockedTogether) {
    const auto hr = make({pd::Industry::HumanResources});
    EXPECT_EQ(blocked(hr, "이 문서는 대외비입니다. 희망퇴직 대상 부서 목록을 정리해 주세요. 날씨가 좋네요."),
              std::vector<std::string>{"이 문서는 대외비입니다. 희망퇴직 대상 부서 목록을 정리해 주세요."});
}

TEST(DetectConfidential, OneSideAloneIsNotBlocked) {
    const auto bank = make({pd::Industry::Bank, pd::Industry::HumanResources});
    for (const std::string_view text : {
             "대외비 문서는 외부 서비스에 올리지 마세요.",
             "인수합병의 일반적인 절차를 설명해 줘.",
             "구조조정이 기업 가치에 미치는 영향은?",
             "대외비 표시 방법을 알려 줘. 오늘 점심 메뉴는 뭐야? 인수합병 뉴스 요약해 줘.",  // 이웃이 아님
         }) {
        EXPECT_TRUE(blocked(bank, text).empty()) << text;
    }
}

TEST(DetectConfidential, OffWithoutSubjects) {
    const auto none = make({});
    EXPECT_TRUE(blocked(none, "대외비인 3분기 잠정 실적 자료").empty());
    // 대상어가 없는 업종을 골라도 꺼져 있다.
    const auto defense = make({pd::Industry::Defense});
    EXPECT_TRUE(blocked(defense, "대외비인 3분기 잠정 실적 자료").empty());
    // 업종 대상어는 그 업종에서만 켜진다.
    const auto hospital = make({pd::Industry::Hospital});
    EXPECT_TRUE(blocked(hospital, "대외비인 3분기 잠정 실적 자료").empty());
    EXPECT_FALSE(blocked(hospital, "대외비: 의료사고 경위서 초안").empty());
}

TEST(DetectConfidential, InstitutionTerms) {
    const auto d = make({}, {"사내비"}, {"한빛 프로젝트"});
    EXPECT_FALSE(blocked(d, "사내비 한빛프로젝트 일정표").empty());
    EXPECT_FALSE(blocked(d, "대외비 한빛 프로젝트 일정표").empty());  // 공통 표지어는 늘 켜짐
    EXPECT_TRUE(blocked(d, "한빛 프로젝트 소개 자료").empty());
}

TEST(DetectConfidential, InvalidTermsAreRejected) {
    pd::InstitutionPolicy blank;
    blank.confidential_subjects = {" "};
    EXPECT_EQ(pd::Detectors::make({}, {}, blank).error(), pc::InputError::EmptyContent);
    pd::InstitutionPolicy broken;
    broken.confidential_markers = {std::string("\xff")};
    EXPECT_EQ(pd::Detectors::make({}, {}, broken).error(), pc::InputError::InvalidUtf8);
}

// 강한 표지어(결정 #224)는 대상어가 없어도 그 낱말을 확인 종류로 낸다. 약한 표지어 홀로는 아무것도 내지 않는다.
TEST(DetectConfidential, StrongMarkerAloneAsksForConfirmation) {
    const auto bank = make({pd::Industry::Bank});
    const auto markers = [&](std::string_view text) {
        std::vector<std::string> out;
        const auto entities = bank.detect_segment(text, pc::SegmentIndex{0});
        EXPECT_TRUE(entities);
        for (const auto& e : *entities) {
            if (e.type() == pc::EntityType::ConfidentialMarker) {
                out.emplace_back(text.substr(e.span().begin().value(), e.span().size()));
            }
        }
        return out;
    };
    EXPECT_EQ(markers("이 문서는 대외비입니다. 내용을 정리해 줘."), std::vector<std::string>{"대외비"});
    EXPECT_EQ(markers("Internal Only: please summarize."), std::vector<std::string>{"Internal Only"});
    EXPECT_EQ(markers("사내 한정 자료입니다."), std::vector<std::string>{"사내 한정"});
    EXPECT_TRUE(markers("비공개 일정은 따로 알려 드립니다.").empty());
    EXPECT_TRUE(make({}).detect_segment("대외비 문서입니다.", pc::SegmentIndex{0})->empty());  // 업종 없으면 꺼짐
}
