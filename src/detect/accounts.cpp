// 계좌번호 세 겹(ADR 0016): 국내 형식표, 외국 구조(IBAN 과 나라별), 계좌 문맥 규칙.
#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>

#include "data/account_context_terms.hpp"
#include "data/foreign_account_formats.hpp"
#include "data/iban_registry.hpp"
#include "data/kr_bank_account_formats.hpp"
#include "rules.hpp"

namespace prompt_airlock::detect::rules {
namespace {

using core::DetectorKind;
using core::EntityType;

void push(std::vector<Hit>& out, std::size_t first, std::size_t last, DetectorKind kind) {
    out.push_back({static_cast<std::uint32_t>(first), static_cast<std::uint32_t>(last), EntityType::BankAccount, kind});
}

[[nodiscard]] bool equals_folded(std::u32string_view text, std::u32string_view word) noexcept {
    return text.size() == word.size() &&
           std::ranges::equal(text, word, [](char32_t a, char32_t b) { return ascii_lower(a) == b; });
}

// 숫자 바로 뒤(공백 하나까지)에 통화 단위, 바로 앞에 통화 기호가 있으면 금액이다(결정 #61).
[[nodiscard]] bool is_amount(std::u32string_view text, std::size_t first, std::size_t last) {
    std::size_t after = last + 1;
    if (after < text.size() && text[after] == U' ') {
        ++after;
    }
    for (const auto unit : data::currency_after) {
        if (after + unit.size() <= text.size() && equals_folded(text.substr(after, unit.size()), unit)) {
            return true;
        }
    }
    std::size_t before = first;
    if (before > 0 && text[before - 1] == U' ') {
        --before;
    }
    for (const auto unit : data::currency_before) {
        if (before >= unit.size() && equals_folded(text.substr(before - unit.size(), unit.size()), unit)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] int number(std::string_view d) noexcept {
    int v = 0;
    for (const char c : d) {
        v = v * 10 + (c - '0');
    }
    return v;
}

// 하이픈·점으로 묶은 유효 날짜 YYYY-MM-DD, YYYY.MM.DD(결정 #61). 묶음 a 부터 세 묶음이 날짜인가.
[[nodiscard]] bool is_date(const DigitRun& run, std::size_t a) noexcept {
    const std::size_t b = a + 2;
    if (b >= run.groups.size()) {
        return false;
    }
    const auto& g = run.groups;
    if (g[a].digits.size() != 4 || g[a + 1].digits.size() != 2 || g[b].digits.size() != 2 ||
        g[a].separator != g[a + 1].separator || (g[a].separator != U'-' && g[a].separator != U'.')) {
        return false;
    }
    const int year = number(g[a].digits);
    const int month = number(g[a + 1].digits);
    const int day = number(g[b].digits);
    constexpr std::array<int, 12> days = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return year >= 1900 && year <= 2099 && month >= 1 && month <= 12 && day >= 1 &&
           day <= days[static_cast<std::size_t>(month - 1)];
}

// 목록 "01,02,710~716" 에 code 가 있는가. ~ 는 같은 자릿수의 범위다.
[[nodiscard]] bool has_code(std::string_view list, std::string_view code) noexcept {
    while (!list.empty()) {
        const auto comma = list.find(',');
        const auto item = list.substr(0, comma);
        const auto tilde = item.find('~');
        if (tilde == std::string_view::npos ? item == code
                                             : code.size() == tilde && item.substr(0, tilde) <= code &&
                                                   code <= item.substr(tilde + 1)) {
            return true;
        }
        if (comma == std::string_view::npos) {
            break;
        }
        list.remove_prefix(comma + 1);
    }
    return false;
}

// 첫 자리 조건 "9" 또는 후보 "8|9".
[[nodiscard]] bool has_prefix(std::string_view d, std::string_view prefixes) noexcept {
    if (prefixes.empty()) {
        return true;
    }
    while (true) {
        const auto bar = prefixes.find('|');
        if (d.starts_with(prefixes.substr(0, bar))) {
            return true;
        }
        if (bar == std::string_view::npos) {
            return false;
        }
        prefixes.remove_prefix(bar + 1);
    }
}

// 묶음 [a, b] 의 길이가 "3-2-5-1" 과 같은가.
[[nodiscard]] bool same_structure(const DigitRun& run, std::size_t a, std::size_t b, std::string_view structure) noexcept {
    std::size_t g = a;
    while (!structure.empty()) {
        const auto dash = structure.find('-');
        const auto part = structure.substr(0, dash);
        std::size_t length = 0;
        for (const char c : part) {
            length = length * 10 + static_cast<std::size_t>(c - '0');
        }
        if (g > b || run.groups[g].digits.size() != length) {
            return false;
        }
        ++g;
        if (dash == std::string_view::npos) {
            break;
        }
        structure.remove_prefix(dash + 1);
    }
    return g == b + 1;
}

// 국내 형식표. 계좌 문맥이 없으면 묶음 구조까지 같게 끊어 쓴 경우만 계좌로 보고(2026-10-18 결정),
// 휴대폰·사업자번호 모양이면 계좌 문맥이 있을 때만 계좌로 본다(ADR 0016 겹침 규칙).
[[nodiscard]] bool matches_domestic(const DigitRun& run, std::size_t a, std::size_t b, std::string_view d,
                                    bool context) noexcept {
    const bool shared = is_phone_number(d) || is_business_number(d);
    return std::ranges::any_of(data::kr_account_formats, [&](const data::KrAccountFormat& f) {
        if (f.digits != d.size() || !has_prefix(d, f.fixed_prefix)) {
            return false;
        }
        if (f.subject_length > 0 && !has_code(f.subject_codes, d.substr(f.subject_offset, f.subject_length))) {
            return false;
        }
        return context || (!f.needs_context && !shared && same_structure(run, a, b, f.structure));
    });
}

// ABA routing: 가중치 3,7,1 합이 10의 배수.
[[nodiscard]] bool is_aba(std::string_view d) noexcept {
    if (d.size() != 9) {
        return false;
    }
    int sum = 0;
    for (std::size_t i = 0; i < 9; ++i) {
        sum += (d[i] - '0') * data::aba_weights[i];
    }
    return sum % 10 == 0;
}

// CLABE: 앞 17자리에 가중치 3,7,1 반복, 검증 자리 = (10 - 합 % 10) % 10.
[[nodiscard]] bool is_clabe(std::string_view d) noexcept {
    if (d.size() != data::clabe_length) {
        return false;
    }
    constexpr std::array<int, 3> w = {3, 7, 1};
    int sum = 0;
    for (std::size_t i = 0; i < 17; ++i) {
        sum += (d[i] - '0') * w[i % 3] % 10;
    }
    return (10 - sum % 10) % 10 == d[17] - '0';
}

// 앵커 [first, last] 가까이(앞뒤 anchor_window) 에서 겹치지 않는 숫자 구간 가운데 자릿수가 [lo, hi] 인 것을 찾는다.
// runs 는 위치 순이다. 창 안에서 시작하는 묶음만 보므로 앵커 하나당 상수 시간이다.
[[nodiscard]] std::optional<std::pair<std::uint32_t, std::uint32_t>> account_near(
    std::span<const DigitRun> runs, std::size_t first, std::size_t last, std::size_t lo, std::size_t hi) {
    const std::size_t from = first > data::anchor_window ? first - data::anchor_window : 0;
    const std::size_t to = last + data::anchor_window;
    auto it = std::ranges::lower_bound(runs, from, {}, [](const DigitRun& r) { return r.groups.back().last_unit; });
    for (; it != runs.end() && it->groups.front().first_unit <= to; ++it) {
        const auto& g = it->groups;
        auto start = std::ranges::lower_bound(g, from, {}, &DigitGroup::first_unit);
        for (auto a = static_cast<std::size_t>(start - g.begin()); a < g.size() && g[a].first_unit <= to; ++a) {
            std::size_t digits = 0;
            for (std::size_t b = a; b < g.size() && g[b].last_unit <= to; ++b) {
                digits += g[b].digits.size();
                if (digits > hi) {
                    break;
                }
                const bool disjoint = g[b].last_unit < first || g[a].first_unit > last;
                if (disjoint && digits >= lo) {
                    return std::pair{g[a].first_unit, g[b].last_unit};
                }
            }
        }
    }
    return std::nullopt;
}

// 앵커가 있는 나라 구조: 묶음 길이와 구분자가 맞는 앵커 + 가까운 계좌 숫자열.
void find_anchored(std::span<const DigitRun> runs, std::vector<Hit>& out) {
    for (const auto& run : runs) {
        const auto& g = run.groups;
        for (std::size_t a = 0; a < g.size(); ++a) {
            for (const auto& f : data::anchored_formats) {
                const std::size_t k = f.groups[2] == 0 ? 2 : 3;
                if (a + k > g.size()) {
                    continue;
                }
                bool ok = true;
                for (std::size_t i = 0; i < k && ok; ++i) {
                    ok = g[a + i].digits.size() == f.groups[i] && (i + 1 == k || g[a + i].separator == f.separator);
                }
                if (!ok) {
                    continue;
                }
                const auto first = g[a].first_unit;
                const auto last = g[a + k - 1].last_unit;
                if (const auto acct = account_near(runs, first, last, f.account_min, f.account_max)) {
                    push(out, first, last, DetectorKind::Pattern);
                    push(out, acct->first, acct->second, DetectorKind::Pattern);
                }
            }
            // 일본: 두 묶음 쌍(지점-계좌, 우체국 기호-번호).
            for (const auto& p : data::jp_pairs) {
                if (a + 1 < g.size() && g[a].digits.size() == p.first && g[a + 1].digits.size() == p.second &&
                    g[a].separator == U'-') {
                    push(out, g[a].first_unit, g[a + 1].last_unit, DetectorKind::Pattern);
                }
            }
        }
    }
}

[[nodiscard]] bool bban_matches(std::u32string_view chars, std::string_view pattern) noexcept {
    std::size_t at = 0;
    for (std::size_t i = 0; i < pattern.size();) {
        std::size_t count = 0;
        while (i < pattern.size() && pattern[i] >= '0' && pattern[i] <= '9') {
            count = count * 10 + static_cast<std::size_t>(pattern[i] - '0');
            ++i;
        }
        if (i < pattern.size() && pattern[i] == '!') {
            ++i;
        }
        const char kind = pattern[i++];
        for (std::size_t j = 0; j < count; ++j, ++at) {
            const char32_t c = chars[at];
            const bool ok = kind == 'n' ? is_ascii_digit(c) : kind == 'a' ? is_ascii_alpha(c) : is_ascii_alnum(c);
            if (!ok) {
                return false;
            }
        }
    }
    return true;
}

// IBAN: 국가 코드 2 + 검증 2 + BBAN. 인쇄 형식처럼 사이에 공백 하나씩 들어가도 된다. mod-97 은 보지 않는다(ADR 0016).
// 국가 구조에 맞지 않아도 IBAN 모양(영문 2 + 숫자 2 + 영숫자 11~30)이고 계좌 문맥이 있으면 차단한다.
void find_ibans(std::u32string_view text, const Nearby& context, std::vector<Hit>& out) {
    constexpr std::size_t max_iban = 34;
    for (std::size_t i = 0; i + 4 <= text.size(); ++i) {
        if ((i > 0 && is_ascii_alnum(text[i - 1])) || !is_ascii_alpha(text[i]) || !is_ascii_alpha(text[i + 1]) ||
            !is_ascii_digit(text[i + 2]) || !is_ascii_digit(text[i + 3])) {
            continue;
        }
        // 영숫자를 모으며 원래 위치를 기억한다. 공백은 하나만 건너뛴다.
        std::u32string chars;
        std::vector<std::size_t> at;
        for (std::size_t j = i; j < text.size() && chars.size() < max_iban;) {
            if (is_ascii_alnum(text[j])) {
                chars.push_back(text[j] >= U'a' ? text[j] - (U'a' - U'A') : text[j]);
                at.push_back(j);
                ++j;
            } else if (text[j] == U' ' && j + 1 < text.size() && is_ascii_alnum(text[j + 1]) && !chars.empty()) {
                ++j;
            } else {
                break;
            }
        }
        // 길이 L 에서 끝나려면 그 다음 글자가 바로 붙은 영숫자가 아니어야 한다.
        const auto ends_at = [&](std::size_t length) {
            const auto next = at[length - 1] + 1;
            return next >= text.size() || !is_ascii_alnum(text[next]);
        };
        const std::u32string_view country = std::u32string_view(chars).substr(0, 2);
        bool matched = false;
        for (const auto& c : data::iban_countries) {
            if (country[0] == static_cast<char32_t>(c.country[0]) && country[1] == static_cast<char32_t>(c.country[1]) &&
                chars.size() >= c.length && ends_at(c.length) &&
                bban_matches(std::u32string_view(chars).substr(4, c.length - 4u), c.bban)) {
                push(out, i, at[c.length - 1], DetectorKind::Pattern);
                matched = true;
            }
        }
        if (!matched && chars.size() >= 15 && ends_at(chars.size()) &&
            context.around(i, at.back(), data::account_context_window)) {
            push(out, i, at.back(), DetectorKind::Context);
        }
        i = at.back();
    }
}

// 인도 IFSC(영문 4 + '0' + 영숫자 6) + 가까운 계좌 숫자열.
void find_ifsc(std::u32string_view text, std::span<const DigitRun> runs, std::vector<Hit>& out) {
    constexpr std::size_t ifsc_length = 11;
    for (std::size_t i = 0; i + ifsc_length <= text.size(); ++i) {
        if (i > 0 && is_ascii_alnum(text[i - 1])) {
            continue;
        }
        const auto t = text.substr(i, ifsc_length);
        const bool shape = std::all_of(t.begin(), t.begin() + 4, is_ascii_alpha) && t[4] == U'0' &&
                           std::all_of(t.begin() + 5, t.end(), is_ascii_alnum) &&
                           (i + ifsc_length == text.size() || !is_ascii_alnum(text[i + ifsc_length]));
        if (!shape) {
            continue;
        }
        if (const auto acct = account_near(runs, i, i + ifsc_length - 1, data::in_account_min, data::in_account_max)) {
            push(out, i, i + ifsc_length - 1, DetectorKind::Pattern);
            push(out, acct->first, acct->second, DetectorKind::Pattern);
        }
        i += ifsc_length - 1;
    }
}

}  // namespace

void find_accounts(std::span<const DigitRun> runs, std::u32string_view text, const TermMatcher& context_terms,
                   const DetectionView& view, std::vector<Hit>& out) {
    const Nearby context(context_terms.find(view));
    // 종결 부호(. ? ! 。) 뒤에 공백이 오면 다음 구절이다. 계좌 문맥은 구절을 넘지 않는다(줄바꿈은 넘는다).
    std::vector<std::uint32_t> clause(text.size() + 1, 0);
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char32_t c = text[i];
        // 영문자 바로 뒤의 마침표는 약어("account no. 123")일 수 있어 구절 끝으로 보지 않는다.
        const bool period = c == U'.' && !(i > 0 && is_ascii_alpha(text[i - 1]));
        const bool end = (period || c == U'?' || c == U'!' || c == U'\u3002') && i + 1 < text.size() &&
                         (text[i + 1] == U' ' || text[i + 1] == U'\n' || text[i + 1] == U'\t');
        clause[i + 1] = clause[i] + (end ? 1U : 0U);
    }
    for (const auto& run : runs) {
        // 날짜에 속한 묶음. 날짜 안의 구간(예: "2026-10")도 문맥 규칙에서 뺀다.
        std::vector<bool> in_date(run.groups.size(), false);
        for (std::size_t g = 0; g < run.groups.size(); ++g) {
            if (is_date(run, g)) {
                in_date[g] = in_date[g + 1] = in_date[g + 2] = true;
            }
        }
        for_each_window(run, [&](std::size_t a, std::size_t b, std::string_view d) {
            const auto first = run.groups[a].first_unit;
            const auto last = run.groups[b].last_unit;
            const bool near = context.around_in_clause(first, last, data::account_context_window, clause);
            // 금액과 날짜는 문맥에 기대는 판정(문맥 규칙, 문맥이 필요한 형식표 행)에서만 뺀다.
            const bool exempt = is_amount(text, first, last) ||
                                std::all_of(in_date.begin() + static_cast<std::ptrdiff_t>(a),
                                            in_date.begin() + static_cast<std::ptrdiff_t>(b) + 1, [](bool v) { return v; });
            const bool usable = near && !exempt;
            // 1. 국내 형식표.
            if (matches_domestic(run, a, b, d, usable)) {
                push(out, first, last, DetectorKind::Pattern);
            }
            // 2. 외국 구조 가운데 숫자만으로 판정하는 것: 멕시코 CLABE, 중국 은행카드, 미국 ABA + 계좌.
            if (is_clabe(d) ||
                (d.starts_with(data::cn_card_prefix) && d.size() >= data::cn_card_min && d.size() <= data::cn_card_max)) {
                push(out, first, last, DetectorKind::Pattern);
            }
            if (a == b && is_aba(d)) {
                if (const auto acct = account_near(runs, first, last, data::us_account_min, data::us_account_max)) {
                    push(out, first, last, DetectorKind::Checksum);
                    push(out, acct->first, acct->second, DetectorKind::Pattern);
                }
            }
            // 3. 계좌 문맥 규칙.
            if (usable && d.size() >= data::context_digits_min && d.size() <= data::context_digits_max) {
                push(out, first, last, DetectorKind::Context);
            }
        });
    }
    find_anchored(runs, out);
    find_ibans(text, context, out);
    find_ifsc(text, runs, out);
}

}  // namespace prompt_airlock::detect::rules
