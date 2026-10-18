// 민감정보: 범주마다 같은 범주어로 통과(특정 개인 표지 없음)·차단(있음) 짝, 직전 문장 창, 통과 집계. 문장은 합성이다.
#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
using pd::SensitiveCategory;

namespace {

const pd::Detectors& detectors() {
    static const auto d = *pd::Detectors::make({});
    return d;
}

std::vector<std::string> sensitive(std::string_view text) {
    std::vector<std::string> out;
    const auto entities = detectors().detect_segment(text, pc::SegmentIndex{0});
    EXPECT_TRUE(entities);
    for (const auto& e : *entities) {
        if (e.type() == pc::EntityType::SensitivePersonalInfo) {
            out.emplace_back(text.substr(e.span().begin().value(), e.span().size()));
        }
    }
    return out;
}

pd::SensitiveTally tally(std::string_view text) {
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts));
    const auto document = *std::move(builder).build();
    return detectors().detect(document)->sensitive_passed;
}

struct Pair {
    SensitiveCategory category;
    std::string_view general;   // 특정 개인 없음: 통과
    std::string_view personal;  // 특정 개인 있음: 차단
};

const std::vector<Pair> pairs = {
    {SensitiveCategory::Health, "당뇨 초기 증상이 궁금합니다.", "김가상 과장은 당뇨 치료 중입니다."},
    {SensitiveCategory::Belief, "불교의 역사를 알려 주세요.", "제가 다니는 교회 이름을 적어 주세요."},
    {SensitiveCategory::LaborUnion, "노동조합 설립 절차는 무엇인가요?", "박가상 대리는 노조 조합원입니다."},
    {SensitiveCategory::PoliticalParty, "당원 모집 공고 예시를 써 주세요.", "저는 진보당 당원입니다."},
    {SensitiveCategory::PoliticalView, "정치 성향 조사 방법을 알려 주세요.", "이가상 주무관은 보수 성향입니다."},
    {SensitiveCategory::SexLife, "성소수자 인권 정책을 요약해 주세요.", "my son is gay."},
    {SensitiveCategory::Genetic, "유전자 검사 종류를 설명해 주세요.", "본인의 유전자 검사 결과를 첨부합니다."},
    {SensitiveCategory::Criminal, "집행유예 기간 계산법은?", "최가상 씨는 집행유예 중입니다."},
    {SensitiveCategory::Biometric, "홍채 인식 기술 동향을 정리해 주세요.", "010-2345-6789 사용자의 홍채 정보입니다."},
    {SensitiveCategory::Ethnicity, "민족 구성 통계를 찾아 주세요.", "정가상 환자의 민족 정보를 입력했습니다."},
};

}  // namespace

TEST(DetectSensitive, CategoryPairs) {
    for (const auto& p : pairs) {
        const auto index = static_cast<std::size_t>(p.category);
        EXPECT_TRUE(sensitive(p.general).empty()) << p.general;
        EXPECT_EQ(tally(p.general).passed[index], 1) << p.general;
        EXPECT_EQ(sensitive(p.personal), std::vector<std::string>{std::string(p.personal)}) << p.personal;
        EXPECT_EQ(tally(p.personal).passed[index], 0) << p.personal;
    }
}

TEST(DetectSensitive, PreviousSentenceWindow) {
    // 주어가 앞 문장에 있어도 두 문장을 함께 막는다.
    const std::string text = "김가상 과장 보고서입니다. 지난주 수술을 받았습니다.";
    EXPECT_EQ(sensitive(text), std::vector<std::string>{text});
    // 두 문장 넘게 떨어지면 단어 규칙으로는 잇지 않는다(Phase 7.5 대상).
    EXPECT_TRUE(sensitive("김가상 과장 보고서입니다. 일정은 다음 주입니다. 수술 일정표를 만들어 주세요.").empty());
}

TEST(DetectSensitive, GenericAddresseesAreNotPersons) {
    EXPECT_TRUE(sensitive("고객님 병원 예약 시스템 점검 안내입니다.").empty());
    EXPECT_TRUE(sensitive("회원님께 치료 안내 문자를 보냅니다.").empty());
    EXPECT_FALSE(sensitive("김가상님 병원 예약을 변경했습니다.").empty());
}

TEST(DetectSensitive, WordsInsideOtherWordsAreNotCategories) {
    for (const std::string_view text : {"김가상 과장이 암호를 바꿨습니다.", "김가상 과장의 정당한 요구입니다.",
                                        "김가상 과장이 서버 장애를 보고했습니다."}) {
        EXPECT_TRUE(sensitive(text).empty()) << text;
    }
}
