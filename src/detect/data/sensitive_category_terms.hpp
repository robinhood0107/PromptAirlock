// 민감정보 범주어(ADR 0016 SensitivePersonalInfo).
// 원천: 범주는 개인정보 보호법 제23조①과 같은 법 시행령 제18조(사상·신념, 노동조합·정당의 가입·탈퇴, 정치적 견해,
//   건강, 성생활 등, 유전정보, 범죄경력자료, 생체인식정보, 인종·민족 정보). 단어는 직접 작성한 사전이다. 확인일 2026-10-18.
// 한 글자 단어와 일상어 일부로 흔히 쓰이는 단어는 넣지 않는다("암"⊂"암호", "정당"⊂"정당한", "장애"⊂"서버 장애",
//   "전과"⊂"전과목", "지문"⊂"국어 지문", "게이"⊂"게이트"). 단어 안 공백은 일치에서 무시된다(terms.hpp).
// 바꾸는 절차: 단어를 더하고 tests/unit/detect_sensitive_test.cpp 의 범주 짝 시험을 돌린 뒤 측정으로 오차단을 다시 잰다.
#pragma once

#include <array>
#include <string_view>

#include "prompt_airlock/detect/sensitive.hpp"

namespace prompt_airlock::detect::data {

using detect::SensitiveCategory;

struct CategoryTerm {
    SensitiveCategory category;
    std::u32string_view term;
};

inline constexpr auto sensitive_terms = std::to_array<CategoryTerm>({
    // 건강
    {SensitiveCategory::Health, U"질병"}, {SensitiveCategory::Health, U"질환"}, {SensitiveCategory::Health, U"진단받"},
    {SensitiveCategory::Health, U"진단서"}, {SensitiveCategory::Health, U"진료"}, {SensitiveCategory::Health, U"병원"},
    {SensitiveCategory::Health, U"입원"}, {SensitiveCategory::Health, U"퇴원"}, {SensitiveCategory::Health, U"수술"},
    {SensitiveCategory::Health, U"치료"}, {SensitiveCategory::Health, U"처방"}, {SensitiveCategory::Health, U"복용"},
    {SensitiveCategory::Health, U"병력"}, {SensitiveCategory::Health, U"장애인"}, {SensitiveCategory::Health, U"장애등급"},
    {SensitiveCategory::Health, U"우울증"}, {SensitiveCategory::Health, U"공황장애"}, {SensitiveCategory::Health, U"조현병"},
    {SensitiveCategory::Health, U"정신과"}, {SensitiveCategory::Health, U"당뇨"}, {SensitiveCategory::Health, U"고혈압"},
    {SensitiveCategory::Health, U"암 진단"}, {SensitiveCategory::Health, U"암환자"}, {SensitiveCategory::Health, U"항암"},
    {SensitiveCategory::Health, U"임신"}, {SensitiveCategory::Health, U"치매"}, {SensitiveCategory::Health, U"확진"},
    {SensitiveCategory::Health, U"에이즈"}, {SensitiveCategory::Health, U"hiv"}, {SensitiveCategory::Health, U"diagnosis"},
    {SensitiveCategory::Health, U"diagnosed"}, {SensitiveCategory::Health, U"cancer"}, {SensitiveCategory::Health, U"diabetes"},
    {SensitiveCategory::Health, U"depression"}, {SensitiveCategory::Health, U"pregnant"},
    {SensitiveCategory::Health, U"hospitalized"},
    // 사상·신념
    {SensitiveCategory::Belief, U"종교"}, {SensitiveCategory::Belief, U"신앙"}, {SensitiveCategory::Belief, U"기독교"},
    {SensitiveCategory::Belief, U"개신교"}, {SensitiveCategory::Belief, U"천주교"}, {SensitiveCategory::Belief, U"불교"},
    {SensitiveCategory::Belief, U"이슬람"}, {SensitiveCategory::Belief, U"무슬림"}, {SensitiveCategory::Belief, U"교회"},
    {SensitiveCategory::Belief, U"성당"}, {SensitiveCategory::Belief, U"사찰"}, {SensitiveCategory::Belief, U"세례"},
    {SensitiveCategory::Belief, U"신자"}, {SensitiveCategory::Belief, U"신념"}, {SensitiveCategory::Belief, U"religion"},
    {SensitiveCategory::Belief, U"christian"}, {SensitiveCategory::Belief, U"buddhist"}, {SensitiveCategory::Belief, U"muslim"},
    // 노동조합
    {SensitiveCategory::LaborUnion, U"노동조합"}, {SensitiveCategory::LaborUnion, U"노조"},
    {SensitiveCategory::LaborUnion, U"조합원"}, {SensitiveCategory::LaborUnion, U"파업"},
    {SensitiveCategory::LaborUnion, U"labor union"}, {SensitiveCategory::LaborUnion, U"trade union"},
    // 정당
    {SensitiveCategory::PoliticalParty, U"정당 가입"}, {SensitiveCategory::PoliticalParty, U"정당원"},
    {SensitiveCategory::PoliticalParty, U"당원"}, {SensitiveCategory::PoliticalParty, U"입당"},
    {SensitiveCategory::PoliticalParty, U"탈당"}, {SensitiveCategory::PoliticalParty, U"지지 정당"},
    {SensitiveCategory::PoliticalParty, U"더불어민주당"}, {SensitiveCategory::PoliticalParty, U"국민의힘"},
    {SensitiveCategory::PoliticalParty, U"조국혁신당"}, {SensitiveCategory::PoliticalParty, U"개혁신당"},
    {SensitiveCategory::PoliticalParty, U"진보당"}, {SensitiveCategory::PoliticalParty, U"정의당"},
    // 정치적 견해
    {SensitiveCategory::PoliticalView, U"정치 성향"}, {SensitiveCategory::PoliticalView, U"정치적 견해"},
    {SensitiveCategory::PoliticalView, U"진보 성향"}, {SensitiveCategory::PoliticalView, U"보수 성향"},
    {SensitiveCategory::PoliticalView, U"지지하는 후보"}, {SensitiveCategory::PoliticalView, U"political view"},
    // 성생활·성적 지향
    {SensitiveCategory::SexLife, U"성생활"}, {SensitiveCategory::SexLife, U"성적 지향"},
    {SensitiveCategory::SexLife, U"성적 취향"}, {SensitiveCategory::SexLife, U"동성애"},
    {SensitiveCategory::SexLife, U"성소수자"}, {SensitiveCategory::SexLife, U"레즈비언"},
    {SensitiveCategory::SexLife, U"양성애"}, {SensitiveCategory::SexLife, U"트랜스젠더"},
    {SensitiveCategory::SexLife, U"성병"}, {SensitiveCategory::SexLife, U"sexual orientation"},
    {SensitiveCategory::SexLife, U"gay"}, {SensitiveCategory::SexLife, U"lesbian"},
    {SensitiveCategory::SexLife, U"transgender"},
    // 유전정보
    {SensitiveCategory::Genetic, U"유전정보"}, {SensitiveCategory::Genetic, U"유전자 검사"},
    {SensitiveCategory::Genetic, U"유전질환"}, {SensitiveCategory::Genetic, U"dna"}, {SensitiveCategory::Genetic, U"genetic"},
    // 범죄경력
    {SensitiveCategory::Criminal, U"범죄경력"}, {SensitiveCategory::Criminal, U"전과자"},
    {SensitiveCategory::Criminal, U"전과 기록"}, {SensitiveCategory::Criminal, U"범죄 기록"},
    {SensitiveCategory::Criminal, U"수감"}, {SensitiveCategory::Criminal, U"복역"}, {SensitiveCategory::Criminal, U"교도소"},
    {SensitiveCategory::Criminal, U"형사처벌"}, {SensitiveCategory::Criminal, U"기소"}, {SensitiveCategory::Criminal, U"실형"},
    {SensitiveCategory::Criminal, U"집행유예"}, {SensitiveCategory::Criminal, U"구속"}, {SensitiveCategory::Criminal, U"체포"},
    {SensitiveCategory::Criminal, U"criminal record"}, {SensitiveCategory::Criminal, U"convicted"},
    // 생체인식
    {SensitiveCategory::Biometric, U"지문정보"}, {SensitiveCategory::Biometric, U"지문인식"},
    {SensitiveCategory::Biometric, U"지문 등록"}, {SensitiveCategory::Biometric, U"홍채"},
    {SensitiveCategory::Biometric, U"안면인식"}, {SensitiveCategory::Biometric, U"얼굴인식"},
    {SensitiveCategory::Biometric, U"정맥인식"}, {SensitiveCategory::Biometric, U"생체정보"},
    {SensitiveCategory::Biometric, U"생체인식"}, {SensitiveCategory::Biometric, U"fingerprint"},
    {SensitiveCategory::Biometric, U"iris"}, {SensitiveCategory::Biometric, U"biometric"},
    // 인종·민족
    {SensitiveCategory::Ethnicity, U"인종"}, {SensitiveCategory::Ethnicity, U"민족"}, {SensitiveCategory::Ethnicity, U"혈통"},
    {SensitiveCategory::Ethnicity, U"race"}, {SensitiveCategory::Ethnicity, U"ethnicity"},
});

}  // namespace prompt_airlock::detect::data
