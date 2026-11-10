// 기밀 문장(ADR 0027): 기밀 표지어와 업종 대상어가 같은 문장(또는 이웃 문장)에 있으면 그 문장을 막는다.
// 원천: 업무 문서에서 쓰는 보안 표기와 업종별 미공개 업무 대상을 직접 모은 사전(결정 #210 의 공공·금융 우선 업종).
// 목록은 측정 전에 #217 에 먼저 올렸다. 확인일 2026-11-02. 규칙마다 출처와 시험은 Phase 11 규칙 원장에 적는다.
// 바꾸는 절차: 단어를 고치고 tests/unit/detect_confidential_test.cpp 와 개발용 셋 측정을 다시 돌린다(전후 수치를 모두 기록).
#pragma once

#include <array>
#include <span>
#include <string_view>

#include "prompt_airlock/detect/institution.hpp"

namespace prompt_airlock::detect::data {

// 업종 공통 기밀 표지어. 업종을 하나라도 고르면 켜진다.
inline constexpr auto confidential_markers = std::to_array<std::u32string_view>({
    U"대외비", U"비공개", U"미공개", U"내부검토용", U"내부용", U"사내한정", U"외부유출금지", U"유출금지", U"공개금지",
    U"배포금지", U"열람제한", U"취급주의", U"보안문서", U"비밀문서", U"기밀", U"극비", U"엠바고", U"confidential",
    U"internal only", U"do not distribute",
});

// 강한 기밀 표지어(결정 #224). 대상어가 없어도 보내기 전에 확인을 받는다.
// 약한 표지어(비공개, 미공개, 내부용 등)는 일반 안내에도 흔해 지금처럼 대상어와 함께일 때만 막는다. 띄어쓰기는 무시한다.
inline constexpr auto strong_confidential_markers = std::to_array<std::u32string_view>({
    U"대외비", U"극비", U"비밀문서", U"보안문서", U"사내한정", U"외부유출금지", U"confidential", U"internal only",
    U"do not distribute",
});

inline constexpr auto public_admin_subjects = std::to_array<std::u32string_view>({
    U"예산편성안", U"예산안초안", U"인사발령안", U"감사결과", U"감사보고서", U"입찰예정가", U"예정가격", U"보도자료초안",
    U"도시계획안", U"징계의결",
});
inline constexpr auto public_enterprise_subjects = std::to_array<std::u32string_view>({
    U"입찰예정가", U"예정가격", U"계약단가", U"협상전략", U"요금인상안", U"사업계획안", U"감사결과",
});
inline constexpr auto hospital_subjects = std::to_array<std::u32string_view>({
    U"의료사고", U"임상시험결과", U"감염발생", U"수가협상", U"의료분쟁",
});
inline constexpr auto human_resources_subjects = std::to_array<std::u32string_view>({
    U"구조조정", U"희망퇴직", U"해고대상", U"임금협상안", U"연봉협상", U"인사평가결과", U"징계대상", U"노조교섭",
});
inline constexpr auto bank_subjects = std::to_array<std::u32string_view>({
    U"인수합병", U"잠정실적", U"실적발표전", U"신용등급", U"여신심사", U"대출심사결과", U"부실채권", U"유상증자",
    U"상장계획",
});
inline constexpr auto card_subjects = std::to_array<std::u32string_view>({
    U"잠정실적", U"수수료인상안", U"가맹점수수료율", U"제휴협상", U"인수합병",
});
inline constexpr auto insurance_subjects = std::to_array<std::u32string_view>({
    U"손해율", U"보험금지급심사", U"인수심사", U"잠정실적", U"인수합병", U"요율인상안",
});

// 업종의 대상어. 아직 대상어가 없는 업종은 빈 목록이다.
[[nodiscard]] constexpr std::span<const std::u32string_view> confidential_subjects(Industry industry) noexcept {
    switch (industry) {
        case Industry::PublicAdmin: return public_admin_subjects;
        case Industry::PublicEnterprise: return public_enterprise_subjects;
        case Industry::Hospital: return hospital_subjects;
        case Industry::HumanResources: return human_resources_subjects;
        case Industry::Bank: return bank_subjects;
        case Industry::Card: return card_subjects;
        case Industry::Insurance: return insurance_subjects;
        case Industry::Defense:
        case Industry::Legal:
        case Industry::School:
        case Industry::Telecom:
        case Industry::Research:
        case Industry::Police:
            return {};
    }
    return {};
}

}  // namespace prompt_airlock::detect::data
