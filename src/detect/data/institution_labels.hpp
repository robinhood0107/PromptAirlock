// 업종별 기관 번호 표지어(ADR 0027). 이 말 뒤에 구분과 번호가 오면 번호를 기관 번호(가명화)로 본다.
// 원천: 업무에서 쓰는 번호 이름을 직접 모은 사전(결정 #210 의 공공·금융 우선 업종). 확인일 2026-11-02.
// 규칙마다 출처와 시험은 Phase 11 규칙 원장에 적는다. 계좌·카드·주민등록·사업자등록 번호는 다른 종류가 잡으므로 넣지 않는다.
// 바꾸는 절차: 단어를 더하고 tests/unit/detect_institution_test.cpp 를 돌린 뒤 공문서 측정(Phase 11-3)으로 오차단을 다시 잰다.
#pragma once

#include <array>
#include <span>
#include <string_view>

#include "prompt_airlock/detect/institution.hpp"

namespace prompt_airlock::detect::data {

inline constexpr auto public_admin_labels = std::to_array<std::u32string_view>({
    U"민원접수번호", U"민원번호", U"접수번호", U"신청번호", U"관리번호", U"고지번호", U"전자납부번호", U"과세번호",
});
inline constexpr auto public_enterprise_labels = std::to_array<std::u32string_view>({
    U"고객번호", U"계약번호", U"발주번호", U"사업번호", U"검침번호", U"관리번호",
});
inline constexpr auto hospital_labels = std::to_array<std::u32string_view>({
    U"차트번호", U"환자번호", U"환자등록번호", U"진료번호", U"병록번호", U"의무기록번호", U"처방번호", U"검체번호",
    U"진료카드번호",
});
inline constexpr auto human_resources_labels = std::to_array<std::u32string_view>({
    U"사번", U"사원번호", U"직원번호", U"직번", U"인사번호", U"임직원번호", U"공무원증번호",
});
inline constexpr auto bank_labels = std::to_array<std::u32string_view>({
    U"여신번호", U"대출번호", U"고객번호", U"고객관리번호", U"거래번호", U"신청번호", U"심사번호", U"계약번호", U"cif",
    U"cif번호",
});
inline constexpr auto card_labels = std::to_array<std::u32string_view>({
    U"승인번호", U"가맹점번호", U"회원번호", U"고객번호", U"신청번호",
});
inline constexpr auto insurance_labels = std::to_array<std::u32string_view>({
    U"증권번호", U"보험증권번호", U"계약번호", U"청구번호", U"사고접수번호", U"사고번호", U"접수번호",
});

// 업종의 표지어. 아직 표지어가 없는 업종은 빈 목록이다.
[[nodiscard]] constexpr std::span<const std::u32string_view> institution_labels(Industry industry) noexcept {
    switch (industry) {
        case Industry::PublicAdmin: return public_admin_labels;
        case Industry::PublicEnterprise: return public_enterprise_labels;
        case Industry::Hospital: return hospital_labels;
        case Industry::HumanResources: return human_resources_labels;
        case Industry::Bank: return bank_labels;
        case Industry::Card: return card_labels;
        case Industry::Insurance: return insurance_labels;
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
