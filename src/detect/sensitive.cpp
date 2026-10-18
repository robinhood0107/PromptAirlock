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
            return true;
        default:
            return false;
    }
}

}  // namespace

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
        if (is_identity(hit.type)) {
            marked[sentence_of(hit.first)] = true;
        }
    }

    // 문장 [a, b] 를 차단한다. 앞뒤 공백은 뺀다.
    std::vector<bool> covered(spans.size(), false);
    const auto block = [&](std::size_t a, std::size_t b) {
        std::uint32_t first = spans[a].first_unit;
        std::uint32_t last = spans[b].end_unit - 1;
        while (first < last && (text[first] == U' ' || text[first] == U'\n' || text[first] == U'\t')) {
            ++first;
        }
        while (last > first && (text[last] == U' ' || text[last] == U'\n' || text[last] == U'\t')) {
            --last;
        }
        out.push_back({first, last, EntityType::SensitivePersonalInfo, DetectorKind::Context});
        for (std::size_t i = a; i <= b; ++i) {
            covered[i] = true;
        }
    };
    for (std::size_t i = 0; i < spans.size(); ++i) {
        if (categories[i] != 0 && marked[i]) {
            block(i, i);
        }
        if (i > 0 && ((categories[i] != 0 && marked[i - 1]) || (marked[i] && categories[i - 1] != 0))) {
            block(i - 1, i);
        }
    }
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
