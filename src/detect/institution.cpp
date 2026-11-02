// 기관 번호(ADR 0027): 업종·기관 표지어 뒤 번호와 기관 형식 마스크.
#include "prompt_airlock/detect/institution.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include "rules.hpp"

namespace prompt_airlock::detect {
namespace {

constexpr std::array<std::pair<Industry, std::string_view>, industry_count> industry_names = {{
    {Industry::PublicAdmin, "public-admin"},
    {Industry::PublicEnterprise, "public-enterprise"},
    {Industry::Hospital, "hospital"},
    {Industry::HumanResources, "human-resources"},
    {Industry::Bank, "bank"},
    {Industry::Card, "card"},
    {Industry::Insurance, "insurance"},
    {Industry::Defense, "defense"},
    {Industry::Legal, "legal"},
    {Industry::School, "school"},
    {Industry::Telecom, "telecom"},
    {Industry::Research, "research"},
    {Industry::Police, "police"},
}};

[[nodiscard]] constexpr bool is_hangul_syllable(char32_t c) noexcept { return c >= 0xAC00 && c <= 0xD7A3; }
[[nodiscard]] constexpr bool is_blank(char32_t c) noexcept { return c == U' ' || c == U'\t'; }
// 번호의 앞뒤 경계. 가명 token 의 무작위 부분은 늘 '_' 뒤에 오므로 '_' 도 막는다(잔여 검사가 token 을 다시 잡지 않게).
[[nodiscard]] constexpr bool is_id_neighbor(char32_t c) noexcept { return is_ascii_alnum(c) || c == U'_'; }
[[nodiscard]] constexpr bool is_id_char(char32_t c) noexcept { return is_ascii_alnum(c) || c == U'-' || c == U'/'; }

constexpr std::size_t min_id_value = 4;
constexpr std::size_t max_id_value = 30;
constexpr std::size_t min_id_digits = 3;

// 표지어 끝(label_end 는 표지어 다음 위치) 뒤의 번호. 구분은 ':' '=' '#' '(' 또는 바로 붙은 은/는/이/가 또는 공백이다.
// 번호는 영문·숫자·'-'·'/' 로 4~30자, 숫자 3개 이상, 영문이나 숫자로 시작한다. 더 길면 번호가 아닌 것으로 본다.
[[nodiscard]] std::optional<std::pair<std::size_t, std::size_t>> value_after(std::u32string_view text,
                                                                           std::size_t label_end) {
    std::size_t i = label_end;
    while (i < text.size() && is_blank(text[i])) {
        ++i;
    }
    const bool spaced = i > label_end;
    if (i < text.size() && std::u32string_view(U":=#(").find(text[i]) != std::u32string_view::npos) {
        ++i;
    } else if (!spaced && i < text.size() && std::u32string_view(U"은는이가").find(text[i]) != std::u32string_view::npos) {
        ++i;
    } else if (!spaced) {
        return std::nullopt;  // 표지어가 다른 말에 붙어 있다(사번호 등)
    }
    while (i < text.size() && is_blank(text[i])) {
        ++i;
    }
    std::size_t end = i;
    while (end < text.size() && end - i <= max_id_value) {
        if (is_id_char(text[end])) {
            ++end;
            continue;
        }
        // 하이픈 뒤에 공백이 끼어도 번호가 이어진다(공문서의 "1AA-2409-   0794254"). 공백은 3개까지.
        std::size_t next = end;
        while (next < text.size() && next - end < 3 && is_blank(text[next])) {
            ++next;
        }
        if (next == end || text[end - 1] != U'-' || next >= text.size() || !is_ascii_alnum(text[next])) {
            break;
        }
        end = next;
    }
    if (end - i > max_id_value || (end < text.size() && text[end] == U'_')) {
        return std::nullopt;
    }
    while (end > i && (text[end - 1] == U'-' || text[end - 1] == U'/')) {
        --end;
    }
    const auto value = text.substr(i, end - i);
    if (value.size() < min_id_value || !is_ascii_alnum(value.front()) ||
        std::ranges::count_if(value, is_ascii_digit) < static_cast<std::ptrdiff_t>(min_id_digits)) {
        return std::nullopt;
    }
    return std::pair{i, end - 1};
}

}  // namespace

std::optional<Industry> industry_from_name(std::string_view name) noexcept {
    for (const auto& [industry, n] : industry_names) {
        if (n == name) {
            return industry;
        }
    }
    return std::nullopt;
}

std::string_view industry_name(Industry industry) noexcept {
    for (const auto& [i, n] : industry_names) {
        if (i == industry) {
            return n;
        }
    }
    return "invalid";
}

std::optional<IdFormat> IdFormat::parse(std::string_view mask) {
    const auto view = make_view(mask);
    if (!view || view->units.empty() || view->units.size() > max_id_format_length) {
        return std::nullopt;
    }
    std::u32string out;
    std::size_t slots = 0;
    for (const auto& unit : view->units) {
        const char32_t c = unit.value;
        if (c < 0x20 || c == 0x7F || c == U' ' || c == 0x3000) {
            return std::nullopt;
        }
        slots += (c == U'#' || c == U'@' || c == U'*') ? 1 : 0;
        out.push_back(ascii_lower(c));
    }
    if (slots < min_id_format_slots || slots == out.size()) {
        return std::nullopt;
    }
    return IdFormat(std::move(out));
}

bool IdFormat::matches_at(std::u32string_view text, std::size_t at) const noexcept {
    if (at > text.size() || text.size() - at < mask_.size()) {
        return false;
    }
    for (std::size_t k = 0; k < mask_.size(); ++k) {
        const char32_t c = text[at + k];
        const char32_t m = mask_[k];
        const bool ok = m == U'#'   ? is_ascii_digit(c)
                        : m == U'@' ? is_ascii_alpha(c)
                        : m == U'*' ? is_ascii_alnum(c)
                                    : ascii_lower(c) == m;
        if (!ok) {
            return false;
        }
    }
    return true;
}

namespace rules {

void find_institution_ids(const DetectionView& view, std::u32string_view text, const TermMatcher& labels,
                          std::span<const IdFormat> formats, std::vector<Hit>& out) {
    for (const auto& hit : labels.find(view)) {
        // 표지어 앞이 한글이면 더 긴 말의 일부다(검사번호 안의 사번).
        if (hit.first_unit > 0 && is_hangul_syllable(text[hit.first_unit - 1])) {
            continue;
        }
        if (const auto value = value_after(text, hit.last_unit + 1)) {
            out.push_back({static_cast<std::uint32_t>(value->first), static_cast<std::uint32_t>(value->second),
                           core::EntityType::InstitutionId, core::DetectorKind::Context});
        }
    }
    for (const auto& format : formats) {
        for (std::size_t at = 0; at + format.size() <= text.size(); ++at) {
            const auto end = at + format.size();
            if ((at > 0 && is_id_neighbor(text[at - 1])) || (end < text.size() && is_id_neighbor(text[end])) ||
                !format.matches_at(text, at)) {
                continue;
            }
            out.push_back({static_cast<std::uint32_t>(at), static_cast<std::uint32_t>(end - 1),
                           core::EntityType::InstitutionId, core::DetectorKind::Pattern});
        }
    }
}

}  // namespace rules
}  // namespace prompt_airlock::detect
