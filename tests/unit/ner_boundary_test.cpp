// NER 경계 다듬기(결정 #107): 모델이 낸 구간을 정답 규칙(어절 단위, 호칭·직함·조사·서술격 조사·법인 표기·부서명 제외)에
// 맞추는지 모델 없이 본다. 문장은 합성이고, 모델이 실제로 낸 모양(일부만, 부호 포함, 꼬리 포함)을 흉내 낸다.
#include "prompt_airlock/ner/boundary.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <string_view>

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pn = prompt_airlock::ner;

namespace {

// text 안에서 model 이 처음 나오는 자리를 모델 구간으로 보고 다듬은 결과의 원문 글을 돌려준다.
std::string trimmed(const std::string& text, const std::string& model, pc::EntityType type = pc::EntityType::Person) {
    const auto view = pd::make_view(text);
    EXPECT_TRUE(view);
    const auto at = text.find(model);
    EXPECT_NE(at, std::string::npos) << model;
    const auto& units = view->units;
    const auto first = std::ranges::find_if(units, [&](const auto& u) { return u.source.begin().value() == at; });
    const auto last = std::ranges::find_if(units, [&](const auto& u) { return u.source.end().value() == at + model.size(); });
    EXPECT_NE(first, units.end());
    EXPECT_NE(last, units.end());
    const auto span = pn::name_span(*view, static_cast<std::uint32_t>(first - units.begin()),
                                    static_cast<std::uint32_t>(last - units.begin()), type);
    if (!span) {
        return "<none>";
    }
    return text.substr(span->begin().value(), span->size());
}

constexpr auto org = pc::EntityType::Organization;

}  // namespace

TEST(NerBoundary, PartialSpansWidenToTheWholeWord) {
    EXPECT_EQ(trimmed("이번 주에 다온제약을 방문한다.", "다", org), "다온제약");  // 처음 나온 "다" 가 모델 구간
    EXPECT_EQ(trimmed("회의록 작성은 권가은 몫이다.", "권가"), "권가은");
    EXPECT_EQ(trimmed("「노나래」라는 이름으로 예약했다.", "노"), "노나래");
}

TEST(NerBoundary, PunctuationAtTheEdgesIsDropped) {
    EXPECT_EQ(trimmed("(주)누리별대학교 대표이사 명의", ")누리별대학교", org), "누리별대학교");
    EXPECT_EQ(trimmed("「김민수」라는 이름", "「김민수」"), "김민수");
    EXPECT_EQ(trimmed("가 ... 나", "..."), "<none>");  // 부호뿐이면 이름이 아니다
}

TEST(NerBoundary, ParticlesHonorificsAndCopulasAreDropped) {
    EXPECT_EQ(trimmed("김민수님께 감사 인사를 전했다.", "김민수님께"), "김민수");
    EXPECT_EQ(trimmed("담당자는 윤서연입니다.", "윤서연입니다"), "윤서연");
    EXPECT_EQ(trimmed("담당은 윤서연이라는 사람", "윤서연이라는"), "윤서연");
    EXPECT_EQ(trimmed("우리 팀은 누리별테크에 다닌다.", "누리별테크에", org), "누리별테크");
}

TEST(NerBoundary, TitlesAttachedOrSpacedAreDropped) {
    EXPECT_EQ(trimmed("신태호주무관과 일정을 논의했다.", "신태호주무관과"), "신태호");
    EXPECT_EQ(trimmed("진지우9팀장과 배포 일정을 맞췄다.", "진지우9"), "진지우");
    EXPECT_EQ(trimmed("Jiho Park 대리가 결재를 요청했다.", "Jiho Park 대리"), "Jiho Park");
    EXPECT_EQ(trimmed("Seoyeon Kwon선임과 일정을 논의했다.", "Seoyeon Kwon선"), "Seoyeon Kwon");
}

TEST(NerBoundary, LegalFormsAndDepartmentsAreDroppedFromOrganizations) {
    EXPECT_EQ(trimmed("주식회사 라온병원에서 견적서를 받았다.", "주식회사 라온병원", org), "라온병원");
    EXPECT_EQ(trimmed("(주)라온대학교 대표이사 명의", "주)라온대학교", org), "라온대학교");
    EXPECT_EQ(trimmed("다온에너지 보안팀에서 점검을 나왔다.", "다온에너지 보안팀", org), "다온에너지");
    EXPECT_EQ(trimmed("하람대학교 산학협력단에 공유했다.", "하람대학교 산학협력단", org), "하람대학교");
}

TEST(NerBoundary, PersonSpansEndingInAnOrganizationTailBecomeOrganizations) {
    const auto type_of = [](const std::string& text, const std::string& name) {
        const auto view = pd::make_view(text);
        const auto at = text.find(name);
        const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{at}, pc::Utf8ByteOffset{at + name.size()});
        return pn::corrected_type(*view, span, pc::EntityType::Person);
    };
    EXPECT_EQ(type_of("우리 팀은 도담디자인에 다닌다.", "도담디자인"), pc::EntityType::Organization);
    EXPECT_EQ(type_of("김민수가 왔다.", "김민수"), pc::EntityType::Person);
    EXPECT_EQ(type_of("이제약을 먹었다.", "이제약"), pc::EntityType::Person);  // 앞말이 한 글자뿐이면 그대로
}

TEST(NerBoundary, DepartmentAloneIsNotAnOrganization) {
    // 보호한 글을 다시 탐지할 때 token 옆 부서명만 기관으로 잡히는 모양.
    EXPECT_EQ(trimmed("⟦ORGANIZATION_KTSEN3ZBEC⟧ 영업본부가 실적을 발표했다.", "영업본부가", org), "<none>");
    EXPECT_EQ(trimmed("⟦ORGANIZATION_KTSEN3ZBEC⟧ 고객센터에 문의했다.", "⟧ 고객센터", org), "<none>");
    EXPECT_EQ(trimmed("한빛센터에서 교육이 열린다.", "한빛센터", org), "한빛센터");  // 앞 낱말이 업무 낱말이 아니면 이름
}

TEST(NerBoundary, NeverCutsBelowTwoCharactersOrIntoOrganizationNames) {
    EXPECT_EQ(trimmed("김대표가 왔다.", "김대표"), "김대표");          // 떼면 한 글자만 남는다
    EXPECT_EQ(trimmed("가온연구원이 발표했다.", "가온연구원", org), "가온연구원");  // 기관명 끝 '연구원' 은 직함이 아니다
    EXPECT_EQ(trimmed("가온팀이 이겼다.", "가온팀", org), "가온팀");        // 띄어 쓴 부서명만 뗀다
}
