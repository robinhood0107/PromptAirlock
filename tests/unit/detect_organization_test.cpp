// 결정론 기관 규칙: 앞말 + 기관 꼬리 어절과 법인 표기 뒤 어절을 찾고, 일반어 + 꼬리는 찾지 않는다. 이름은 합성이다.
#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

#include "prompt_airlock/detect/organization.hpp"

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;

namespace {

std::vector<std::string> organizations(std::string_view text) {
    static const auto d = *pd::Detectors::make({});
    const auto found = d.detect_segment(text, pc::SegmentIndex{0});
    EXPECT_TRUE(found);
    std::vector<std::string> out;
    for (const auto& e : *found) {
        if (e.type() == pc::EntityType::Organization) {
            out.emplace_back(text.substr(e.span().begin().value(), e.span().size()));
        }
    }
    return out;
}

using Names = std::vector<std::string>;

}  // namespace

TEST(DetectOrganization, NameHeadPlusTail) {
    EXPECT_EQ(organizations("다음 주에 바름제약을 방문한다."), Names{"바름제약"});
    EXPECT_EQ(organizations("우리 팀은 은하수해운에 다닌다."), Names{"은하수해운"});
    EXPECT_EQ(organizations("「Bluewave솔루션즈」 담당자 회의가 있다."), Names{"Bluewave솔루션즈"});
    EXPECT_EQ(organizations("「Nova랩스」 담당자"), Names{"Nova랩스"});
    EXPECT_EQ(organizations("ＮＸ시스템즈가 신제품을 냈다."), Names{"ＮＸ시스템즈"});  // 전각은 정규화 뒤 반각으로 본다
    EXPECT_EQ(organizations("하람대학교 산학협력단"), Names{"하람대학교"});
}

TEST(DetectOrganization, WordAfterALegalForm) {
    EXPECT_EQ(organizations("주식회사 라온에서 견적서를 받았다."), Names{"라온"});
    EXPECT_EQ(organizations("(주)가온누리 대표이사 명의"), Names{"가온누리"});
}

TEST(DetectOrganization, GenericWordsWithATailAreNotNames) {
    for (const std::string_view text : {"종합병원에 다녀왔다.", "시중은행 금리가 올랐다.", "병원 예약 시스템은 맑다.",
                                        "국립대학교 입학 설명회", "신용카드 사용 내역", "대학교 입학 설명회", "제약 회사"}) {
        EXPECT_TRUE(organizations(text).empty()) << text;
    }
}

TEST(DetectOrganization, TailLists) {
    EXPECT_EQ(pd::org_tail_length(U"바름제약", pd::OrgTails::Strict), 2u);
    EXPECT_EQ(pd::org_tail_length(U"도담디자인", pd::OrgTails::Strict), 0u);  // 일반어와 잘 붙는 꼬리는 엄격 목록에 없다
    EXPECT_EQ(pd::org_tail_length(U"도담디자인", pd::OrgTails::Broad), 3u);
    EXPECT_EQ(pd::org_tail_length(U"은하수정보기술", pd::OrgTails::Strict), 4u);  // 가장 긴 꼬리
}
