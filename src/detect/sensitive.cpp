// 민감정보(ADR 0016): 문장 단위, 직전 문장까지. 같은 창에 특정 개인 표지와 범주어가 함께 있으면 차단하고,
// 범주어만 있으면 통과시키되 범주별 문장 수를 센다(값은 남기지 않는다).
#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

#include "data/personal_markers.hpp"
#include "data/sensitive_category_terms.hpp"
#include "rules.hpp"

namespace prompt_airlock::detect::rules {
namespace {

using core::DetectorKind;
using core::EntityType;

[[nodiscard]] constexpr bool is_hangul_syllable(char32_t c) noexcept { return c >= 0xAC00 && c <= 0xD7A3; }

// 호칭 앞(공백 하나까지)에 한글 2~4음절 이름 모양이 있는가. 일반 호칭(고객, 회원 등)은 이름이 아니다.
[[nodiscard]] bool has_name_before(std::u32string_view text, std::size_t first) noexcept {
    std::size_t end = first;
    if (end > 0 && text[end - 1] == U' ') {
        --end;
    }
    std::size_t begin = end;
    while (begin > 0 && is_hangul_syllable(text[begin - 1]) && end - begin < data::name_max_syllables + 1) {
        --begin;
    }
    const std::size_t length = end - begin;
    if (length < data::name_min_syllables || length > data::name_max_syllables) {
        return false;
    }
    const auto word = text.substr(begin, length);
    return std::ranges::find(data::generic_addressees, word) == data::generic_addressees.end();
}

// 개인 표지로 쓰는 다른 탐지기 결과(식별 정보).
[[nodiscard]] constexpr bool is_identity(EntityType type) noexcept {
    switch (type) {
        case EntityType::Person:
        case EntityType::KoreanPhone:
        case EntityType::KoreanRrn:
        case EntityType::Email:
        case EntityType::CardNumber:
        case EntityType::BankAccount:
        case EntityType::KoreanPassportNo:
        case EntityType::KoreanDriverLicenseNo:
        case EntityType::KoreanAlienRegistrationNo:
        case EntityType::InstitutionId:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool is_document_heading(std::u32string_view text, const Hit& hit) {
    if (hit.type != EntityType::Person || hit.kind != DetectorKind::Ner) return false;
    std::size_t first = hit.first;
    while (first > 0 && hit.first - first < 16 && text[first] != U'(' && text[first] != U'\n') --first;
    if (text[first] != U'(') return false;
    std::u32string label;
    for (std::size_t i = first + 1; i < text.size() && i - first <= 32; ++i) {
        const auto c = text[i];
        if (c == U')') {
            return hit.last < i && std::ranges::find(data::generic_document_headings, label) !=
                                       data::generic_document_headings.end();
        }
        if (is_hangul_syllable(c)) label.push_back(c);
        else if (c != U' ' && c != U'\t' && c != U'·' && c != U'ㆍ' && c != U'\u119E') return false;
    }
    return false;
}

// 짧은 정수 칸이 여러 개인 집계 행은 개인 표지가 아니다. 번호 자체의 차단 결과는 지우지 않는다.
[[nodiscard]] bool is_aggregate_count_row(std::u32string_view text, const Hit& hit) {
    if (core::default_action(hit.type) != core::Action::Block) return false;
    const auto before = text.rfind(U'\n', hit.first);
    const auto first = before == std::u32string_view::npos ? 0 : before + 1;
    const auto after = text.find(U'\n', hit.first);
    const auto end = after == std::u32string_view::npos ? text.size() : after;
    if (hit.last >= end) return false;
    const auto line = text.substr(first, end - first);
    const auto number = line.find_first_of(U"0123456789");
    if (number == std::u32string_view::npos) return false;
    const auto blank = [](char32_t c) { return is_term_space(c) || c == U'\r'; };
    auto label = line.substr(0, number);
    while (!label.empty() && blank(label.back())) label.remove_suffix(1);
    if (!label.ends_with(U" 수") && !label.ends_with(U" 인원")) return false;
    std::size_t cells = 0, digits = 0;
    for (const auto c : line.substr(number)) {
        if (c >= U'0' && c <= U'9') {
            if (digits++ == 0) ++cells;
            if (digits > 3) return false;
        } else if (blank(c)) digits = 0;
        else return false;
    }
    return cells >= 3;
}

}  // namespace

std::vector<bool> block_sentence_pairs(std::span<const SentenceSpan> spans, std::u32string_view text,
                                       const std::vector<bool>& a, const std::vector<bool>& b, EntityType type,
                                       std::vector<Hit>& out) {
    // 문장 [first_sentence, last_sentence] 를 차단한다. 앞뒤 공백은 뺀다.
    std::vector<bool> covered(spans.size(), false);
    const auto block = [&](std::size_t first_sentence, std::size_t last_sentence) {
        std::uint32_t first = spans[first_sentence].first_unit;
        std::uint32_t last = spans[last_sentence].end_unit - 1;
        while (first < last && (text[first] == U' ' || text[first] == U'\n' || text[first] == U'\t')) {
            ++first;
        }
        while (last > first && (text[last] == U' ' || text[last] == U'\n' || text[last] == U'\t')) {
            --last;
        }
        out.push_back({first, last, type, DetectorKind::Context});
        for (std::size_t i = first_sentence; i <= last_sentence; ++i) {
            covered[i] = true;
        }
    };
    for (std::size_t i = 0; i < spans.size(); ++i) {
        if (a[i] && b[i]) {
            block(i, i);
        }
        if (i > 0 && ((a[i] && b[i - 1]) || (b[i] && a[i - 1]))) {
            block(i - 1, i);
        }
    }
    return covered;
}

void find_sensitive(const DetectionView& view, std::u32string_view text, const SensitiveMatchers& matchers,
                    std::span<const Hit> identities, std::vector<Hit>& out, SensitiveTally& tally) {
    const auto spans = sentences(view);
    if (spans.empty()) {
        return;
    }
    const auto sentence_of = [&](std::uint32_t unit) {
        const auto it = std::ranges::upper_bound(spans, unit, {}, &SentenceSpan::first_unit);
        return static_cast<std::size_t>(it - spans.begin()) - 1;
    };
    std::vector<std::uint16_t> categories(spans.size(), 0);
    std::vector<bool> marked(spans.size(), false);
    for (const auto& hit : matchers.categories.find(view)) {
        const auto category = data::sensitive_terms[hit.term].category;
        categories[sentence_of(hit.first_unit)] |= static_cast<std::uint16_t>(1U << static_cast<unsigned>(category));
    }
    for (const auto& hit : matchers.honorifics.find(view)) {
        if (has_name_before(text, hit.first_unit)) {
            marked[sentence_of(hit.first_unit)] = true;
        }
    }
    for (const auto& hit : matchers.self_statements.find(view)) {
        marked[sentence_of(hit.first_unit)] = true;
    }
    for (const auto& hit : identities) {
        if (is_identity(hit.type) && !is_document_heading(text, hit) && !is_aggregate_count_row(text, hit)) {
            marked[sentence_of(hit.first)] = true;
        }
    }

    std::vector<bool> has_category(spans.size(), false);
    for (std::size_t i = 0; i < spans.size(); ++i) {
        has_category[i] = categories[i] != 0;
    }
    const auto covered = block_sentence_pairs(spans, text, has_category, marked, EntityType::SensitivePersonalInfo, out);
    for (std::size_t i = 0; i < spans.size(); ++i) {
        if (covered[i]) {
            continue;
        }
        for (std::size_t c = 0; c < sensitive_category_count; ++c) {
            if ((categories[i] >> c & 1U) != 0 && tally.passed[c] < UINT16_MAX) {
                ++tally.passed[c];
            }
        }
    }
}

}  // namespace prompt_airlock::detect::rules
