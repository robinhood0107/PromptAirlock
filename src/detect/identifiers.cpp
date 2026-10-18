// 숫자 번호 탐지: 전화, 주민등록·외국인등록, 사업자, 카드, 운전면허, 여권.
#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>

#include "data/kr_identifier_formats.hpp"
#include "prompt_airlock/detect/scan.hpp"
#include "rules.hpp"

namespace prompt_airlock::detect::rules {
namespace {

using core::DetectorKind;
using core::EntityType;

[[nodiscard]] int two_digits(std::string_view d, std::size_t at) noexcept {
    return (d[at] - '0') * 10 + (d[at + 1] - '0');
}

[[nodiscard]] bool starts_with_any(std::string_view d, auto const& prefixes) noexcept {
    return std::ranges::any_of(prefixes, [d](std::string_view p) { return d.starts_with(p); });
}

}  // namespace

// 전기통신번호관리세칙의 번호 대역(data/kr_identifier_formats.hpp).
bool is_phone_number(std::string_view d) noexcept {
    const auto n = d.size();
    if (d.starts_with("010")) {
        return n == 11 && d[3] >= '2';
    }
    if (starts_with_any(d, data::legacy_mobile_prefixes)) {
        return n == 10 || n == 11;
    }
    if (d.starts_with("070")) {
        return n == 11;
    }
    if (d.starts_with("050")) {
        return n == 11 || n == 12;
    }
    if (d.starts_with("02")) {
        return n == 9 || n == 10;
    }
    return starts_with_any(d, data::area_codes) && (n == 10 || n == 11);
}

namespace {

[[nodiscard]] bool is_valid_date(int year, int month, int day) noexcept {
    if (month < 1 || month > 12 || day < 1) {
        return false;
    }
    constexpr std::array<int, 12> days = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    return day <= days[static_cast<std::size_t>(month - 1)] + (month == 2 && leap ? 1 : 0);
}

// 주민등록번호·외국인등록번호 구조(gap-review G3, ADR 0016): 생년월일 6 + 성별 자리 1~8 + 6.
// 2020년 10월 이후 번호는 뒷자리가 임의라 검증 자리는 보지 않는다.
[[nodiscard]] std::optional<EntityType> resident_type(std::string_view d) noexcept {
    if (d.size() != 13) {
        return std::nullopt;
    }
    const int g = d[6] - '0';
    if (g < 1 || g > 8) {
        return std::nullopt;
    }
    const int century = (g == 1 || g == 2 || g == 5 || g == 6) ? 1900 : 2000;
    if (!is_valid_date(century + two_digits(d, 0), two_digits(d, 2), two_digits(d, 4))) {
        return std::nullopt;
    }
    return g <= 4 ? EntityType::KoreanRrn : EntityType::KoreanAlienRegistrationNo;
}

}  // namespace

// 사업자등록번호 10자리 검증 자리(공개 계산식, 가중치 1,3,7,1,3,7,1,3,5).
bool is_business_number(std::string_view d) noexcept {
    if (d.size() != 10) {
        return false;
    }
    constexpr std::array<int, 9> w = {1, 3, 7, 1, 3, 7, 1, 3, 5};
    int sum = 0;
    for (std::size_t i = 0; i < 9; ++i) {
        sum += (d[i] - '0') * w[i];
    }
    sum += (d[8] - '0') * 5 / 10;
    return (10 - sum % 10) % 10 == d[9] - '0';
}

namespace {

// 카드번호: 13~19자리, Luhn(ISO/IEC 7812-1). 0 으로 시작하는 번호는 카드 발급자 번호가 아니다.
[[nodiscard]] bool is_card(std::string_view d) noexcept {
    if (d.size() < 13 || d.size() > 19 || d[0] == '0') {
        return false;
    }
    int sum = 0;
    bool twice = false;
    for (auto it = d.rbegin(); it != d.rend(); ++it, twice = !twice) {
        int v = *it - '0';
        if (twice) {
            v = v * 2 > 9 ? v * 2 - 9 : v * 2;
        }
        sum += v;
    }
    return sum % 10 == 0;
}

[[nodiscard]] bool is_license_region(std::string_view d) noexcept {
    const int r = two_digits(d, 0);
    return r >= data::license_region_min && r <= data::license_region_max;
}

// first 앞(공백 하나까지 건너뜀)에 지역 글자가 있으면 그 시작 위치.
[[nodiscard]] std::optional<std::uint32_t> region_name_before(std::u32string_view text, std::uint32_t first) {
    std::uint32_t end = first;
    if (end > 0 && text[end - 1] == U' ') {
        --end;
    }
    for (const auto name : data::license_region_names) {
        if (end >= name.size() && text.substr(end - name.size(), name.size()) == name) {
            return static_cast<std::uint32_t>(end - name.size());
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool keyword_before(std::u32string_view text, std::uint32_t first) {
    const std::size_t from = first > data::license_keyword_window ? first - data::license_keyword_window : 0;
    return text.substr(from, first - from).find(data::license_keyword) != std::u32string_view::npos;
}

void check_window(const DigitRun& run, std::size_t a, std::size_t b, std::string_view d, std::u32string_view text,
                  std::vector<Hit>& out) {
    const auto first = run.groups[a].first_unit;
    const auto last = run.groups[b].last_unit;
    const auto hit = [&](EntityType type, DetectorKind kind) { out.push_back({first, last, type, kind}); };

    // 국가번호 82 로 시작하면 앞자리 0 을 붙여 국내 번호로 본다(+82 10-...).
    if (is_phone_number(d) || (d.starts_with("82") && d.size() >= 10 && is_phone_number("0" + std::string(d.substr(2))))) {
        hit(EntityType::KoreanPhone, DetectorKind::Pattern);
    }
    if (const auto type = resident_type(d)) {
        hit(*type, DetectorKind::Pattern);
    }
    if (is_business_number(d)) {
        hit(EntityType::KoreanBusinessNo, DetectorKind::Checksum);
    }
    if (is_card(d)) {
        hit(EntityType::CardNumber, DetectorKind::Checksum);
    }
    const std::size_t groups = b - a + 1;
    const auto length = [&](std::size_t i) { return run.groups[a + i].digits.size(); };
    // 지역 번호형: 2-2-6-2 로 끊어 썼거나, 붙여 썼으면 앞에 "면허"가 있을 때.
    if (d.size() == 12 && is_license_region(d) &&
        ((groups == 4 && length(0) == 2 && length(1) == 2 && length(2) == 6 && length(3) == 2) ||
         (groups == 1 && keyword_before(text, first)))) {
        hit(EntityType::KoreanDriverLicenseNo, DetectorKind::Pattern);
    }
    // 지역 글자형(2014년 이전): "서울 95-255933-61".
    if (d.size() == 10 && a == 0) {
        if (const auto name = region_name_before(text, first)) {
            out.push_back({*name, last, EntityType::KoreanDriverLicenseNo, DetectorKind::Pattern});
        }
    }
}

[[nodiscard]] bool is_passport_letter(char32_t c) noexcept {
    const auto upper = static_cast<char>(c >= U'a' ? c - (U'a' - U'A') : c);
    return data::passport_type_letters.find(upper) != std::string_view::npos;
}

// 여권번호: 영숫자 9자 묶음이 영문 1 + 숫자 8, 또는 영문 1 + 숫자 3 + 영문 1 + 숫자 4.
void find_passports(std::u32string_view text, std::vector<Hit>& out) {
    std::size_t i = 0;
    while (i < text.size()) {
        if (!is_ascii_alnum(text[i])) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < text.size() && is_ascii_alnum(text[j])) {
            ++j;
        }
        const auto t = text.substr(i, j - i);
        if (t.size() == 9 && is_ascii_alpha(t[0]) && is_passport_letter(t[0])) {
            const auto digits = [&](std::size_t from, std::size_t to) {
                return std::all_of(t.begin() + static_cast<std::ptrdiff_t>(from),
                                   t.begin() + static_cast<std::ptrdiff_t>(to), is_ascii_digit);
            };
            if (digits(1, 9) || (digits(1, 4) && is_ascii_alpha(t[4]) && digits(5, 9))) {
                out.push_back({static_cast<std::uint32_t>(i), static_cast<std::uint32_t>(j - 1),
                               EntityType::KoreanPassportNo, DetectorKind::Pattern});
            }
        }
        i = j;
    }
}

}  // namespace

void find_identifiers(std::span<const DigitRun> runs, std::u32string_view text, std::vector<Hit>& out) {
    for (const auto& run : runs) {
        for_each_window(run, [&](std::size_t a, std::size_t b, std::string_view d) { check_window(run, a, b, d, text, out); });
    }
    find_passports(text, out);
}

}  // namespace prompt_airlock::detect::rules
