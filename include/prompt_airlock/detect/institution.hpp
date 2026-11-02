// 기관 정책 묶음(ADR 0027). 업종을 고르면 그 업종 표지어가 켜지고, 기관이 표지어와 형식 마스크를 더한다.
// 표지어와 마스크로 기관 번호(INSTITUTION_ID, 가명화)를, 기밀 표지어와 대상어로 기밀 문장(CONFIDENTIAL_MATTER, 차단)을 찾는다.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace prompt_airlock::detect {

enum class Industry : std::uint8_t {
    PublicAdmin,       // 지자체·행정
    PublicEnterprise,  // 공기업
    Hospital,          // 병원
    HumanResources,    // 인사·노무(업종 공통)
    Bank,
    Card,
    Insurance,
    Defense,  // 아래는 이름만 받고 표지어는 아직 없다(Phase 11 5절)
    Legal,
    School,
    Telecom,
    Research,
    Police,
};
inline constexpr std::size_t industry_count = 13;

// 설정에 쓰는 이름(public-admin, bank 등). 모르는 이름이면 nullopt.
[[nodiscard]] std::optional<Industry> industry_from_name(std::string_view name) noexcept;
[[nodiscard]] std::string_view industry_name(Industry industry) noexcept;

// 고정 상한. 마스크는 기관 설정에서 오지만 탐지 시간이 글 길이 x 마스크 길이 x 마스크 수로 묶이게 한다.
inline constexpr std::size_t max_id_formats = 16;
inline constexpr std::size_t max_id_format_length = 40;  // 글자 수
inline constexpr std::size_t min_id_format_slots = 4;
inline constexpr std::size_t max_id_labels = 256;
inline constexpr std::size_t max_id_label_length = 32;  // 글자 수
inline constexpr std::size_t max_confidential_terms = 256;  // 표지어·대상어 각각, 길이는 max_id_label_length

// 형식 마스크. # 숫자, @ 영문, * 숫자나 영문, 나머지 글자는 그대로(영문은 대소문자 무시). 정규식이 아니다.
// 자리 글자가 min_id_format_slots 개 이상, 그대로 쓰는 글자가 1개 이상이어야 하고 공백·제어 문자는 받지 않는다.
class IdFormat {
public:
    [[nodiscard]] static std::optional<IdFormat> parse(std::string_view mask);
    // text 의 at 에서 시작해 마스크와 맞으면 true. 경계는 부르는 쪽이 본다.
    [[nodiscard]] bool matches_at(std::u32string_view text, std::size_t at) const noexcept;
    [[nodiscard]] std::size_t size() const noexcept { return mask_.size(); }

private:
    explicit IdFormat(std::u32string mask) : mask_(std::move(mask)) {}
    std::u32string mask_;  // NFKC, 그대로 쓰는 영문은 소문자
};

struct InstitutionPolicy {
    std::vector<Industry> industries;
    std::vector<std::string> id_labels;  // 기관이 더하는 표지어(UTF-8)
    std::vector<IdFormat> id_formats;
    std::vector<std::string> confidential_markers;   // 기관이 더하는 기밀 표지어
    std::vector<std::string> confidential_subjects;  // 기관이 더하는 기밀 대상어
};

}  // namespace prompt_airlock::detect
