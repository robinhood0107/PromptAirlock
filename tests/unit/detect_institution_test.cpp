// 기관 번호(ADR 0027): 업종 표지어 뒤 번호, 기관 표지어, 형식 마스크, 경계와 token 안 글자. 값은 합성이다.
#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;

namespace {

pd::Detectors make(std::vector<pd::Industry> industries, std::vector<std::string> labels = {},
                   std::vector<std::string_view> masks = {}) {
    pd::InstitutionPolicy policy{std::move(industries), std::move(labels), {}};
    for (const auto m : masks) {
        policy.id_formats.push_back(*pd::IdFormat::parse(m));
    }
    return *pd::Detectors::make({}, {}, policy);
}

std::vector<std::string> ids(const pd::Detectors& d, std::string_view text) {
    std::vector<std::string> out;
    const auto entities = d.detect_segment(text, pc::SegmentIndex{0});
    EXPECT_TRUE(entities);
    for (const auto& e : *entities) {
        if (e.type() == pc::EntityType::InstitutionId) {
            out.emplace_back(text.substr(e.span().begin().value(), e.span().size()));
        }
    }
    return out;
}

const pd::Detectors& all_deep() {
    static const auto d = make({pd::Industry::PublicAdmin, pd::Industry::PublicEnterprise, pd::Industry::Hospital,
                                pd::Industry::HumanResources, pd::Industry::Bank, pd::Industry::Card,
                                pd::Industry::Insurance});
    return d;
}

}  // namespace

TEST(DetectInstitution, LabelledNumbers) {
    const std::vector<std::pair<std::string_view, std::string_view>> cases = {
        {"차트번호: 20231234 환자 기록을 정리해 줘", "20231234"},
        {"환자등록번호 00912345 의 처방 내역", "00912345"},
        {"사번은 A10293 입니다", "A10293"},
        {"직원번호(HR-2024-117) 확인 부탁", "HR-2024-117"},
        {"여신번호 LN-2024-00123 심사 의견을 써 줘", "LN-2024-00123"},
        {"CIF: 7781203345", "7781203345"},
        {"증권번호=PL20240099 계약 해지", "PL20240099"},
        {"민원접수번호 2024-000123 처리 결과", "2024-000123"},
        {"고객번호 ８８１２３４５６", "８８１２３４５６"},  // 전각 숫자도 NFKC 로 같은 글자다
        {"사고 접수번호: 2024/11/0099", "2024/11/0099"},
    };
    for (const auto& [text, value] : cases) {
        const auto found = ids(all_deep(), text);
        EXPECT_NE(std::ranges::find(found, std::string(value)), found.end()) << text;
    }
}

TEST(DetectInstitution, NotNumbers) {
    for (const std::string_view text : {
             "차트번호를 어디서 확인하나요",
             "사번은 입사 후 발급됩니다",
             "차트번호 123",                // 숫자 3개뿐이라도 4자 미만
             "여신번호 ABCDEF",             // 숫자 없음
             "검사번호 20231234",           // '사번' 이 더 긴 말 안에 있다
             "사번호 20231234",             // 표지어가 다른 말에 붙음
             "고객번호 1234567890123456789012345678901",  // 30자 초과
             "접수번호 2024_000123",
         }) {
        EXPECT_TRUE(ids(all_deep(), text).empty()) << text;
    }
}

TEST(DetectInstitution, IndustryOffMeansNoLabels) {
    const auto none = make({});
    EXPECT_TRUE(ids(none, "차트번호: 20231234").empty());
    const auto bank = make({pd::Industry::Bank});
    EXPECT_TRUE(ids(bank, "차트번호: 20231234").empty());
    EXPECT_EQ(ids(bank, "여신번호 LN-2024-00123"), std::vector<std::string>{"LN-2024-00123"});
    // 아직 표지어가 없는 업종은 받기만 하고 아무것도 켜지 않는다.
    const auto defense = make({pd::Industry::Defense});
    EXPECT_TRUE(ids(defense, "군번 12-34567890").empty());
}

TEST(DetectInstitution, InstitutionLabels) {
    const auto d = make({}, {"학번", "연구 과제 번호"});
    EXPECT_EQ(ids(d, "학번: 20241234"), std::vector<std::string>{"20241234"});
    EXPECT_EQ(ids(d, "연구과제번호 RS-2024-00412"), std::vector<std::string>{"RS-2024-00412"});
}

TEST(DetectInstitution, InvalidLabelsAreRejected) {
    pd::InstitutionPolicy blank{{}, {" "}, {}};
    EXPECT_EQ(pd::Detectors::make({}, {}, blank).error(), pc::InputError::EmptyContent);
    pd::InstitutionPolicy broken{{}, {std::string("\xff")}, {}};
    EXPECT_EQ(pd::Detectors::make({}, {}, broken).error(), pc::InputError::InvalidUtf8);
}

TEST(DetectInstitution, FormatMasks) {
    const auto d = make({}, {}, {"HR-####-###", "K-@@*###"});
    EXPECT_EQ(ids(d, "담당 HR-2024-117 님"), std::vector<std::string>{"HR-2024-117"});
    EXPECT_EQ(ids(d, "담당 hr-2024-117 님"), std::vector<std::string>{"hr-2024-117"});  // 영문은 대소문자 무시
    EXPECT_EQ(ids(d, "코드 K-AB9123 처리"), std::vector<std::string>{"K-AB9123"});
    EXPECT_TRUE(ids(d, "XHR-2024-117").empty());   // 앞이 영문
    EXPECT_TRUE(ids(d, "HR-2024-1179").empty());   // 뒤가 숫자
    EXPECT_TRUE(ids(d, "HR-20a4-117").empty());
}

TEST(DetectInstitution, MaskNeverMatchesInsideToken) {
    // 가명 token 의 무작위 부분은 '_' 뒤 10글자다. 그 모양의 마스크라도 잔여 검사에서 token 을 다시 잡으면 안 된다.
    const auto d = make({pd::Industry::Bank}, {}, {"7Q2*******"});
    EXPECT_TRUE(ids(d, "고객 ⟦INSTITUTION_ID_7Q2MK4XD9A⟧ 의 여신").empty());
    EXPECT_TRUE(ids(d, "여신번호 ⟦INSTITUTION_ID_7Q2MK4XD9A⟧").empty());
    EXPECT_EQ(ids(d, "코드 7Q2MK4XD9A"), std::vector<std::string>{"7Q2MK4XD9A"});
}

TEST(DetectInstitution, MaskGrammar) {
    for (const std::string_view ok : {"HR-####", "####-@@", "*-***", "ＨＲ－＃＃＃＃"}) {
        EXPECT_TRUE(pd::IdFormat::parse(ok)) << ok;
    }
    for (const std::string_view bad : {
             "", "####", "###-", "HR- ####", "HR-\t####", "HR-###",
             "#########################################-",  // 41자
             "\xff####-",
         }) {
        EXPECT_FALSE(pd::IdFormat::parse(bad)) << bad;
    }
}

TEST(DetectInstitution, IndustryNames) {
    for (std::size_t i = 0; i < pd::industry_count; ++i) {
        const auto industry = static_cast<pd::Industry>(i);
        EXPECT_EQ(pd::industry_from_name(pd::industry_name(industry)), industry);
    }
    EXPECT_FALSE(pd::industry_from_name("Bank"));
    EXPECT_FALSE(pd::industry_from_name("unknown"));
}
