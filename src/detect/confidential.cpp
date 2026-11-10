// 기밀 문장(ADR 0027): 기밀 표지어와 업종·기관 대상어가 같은 문장이나 이웃 문장에 함께 있으면 그 문장을 차단한다.
// 한쪽만 있으면 막지 않는다. 다만 강한 표지어("대외비", "극비" 등)는 대상어가 없어도 보내기 전에 확인을 받는다(결정 #224).
#include <algorithm>
#include <cstdint>
#include <vector>

#include "rules.hpp"

namespace prompt_airlock::detect::rules {

void find_confidential(const DetectionView& view, std::u32string_view text, const TermMatcher& markers,
                       const TermMatcher& subjects, const TermMatcher& strong, std::vector<Hit>& out) {
    if (subjects.empty()) {
        return;  // 업종도 기관 대상어도 없으면 규칙이 꺼져 있다
    }
    for (const auto& hit : strong.find(view)) {
        out.push_back({hit.first_unit, hit.last_unit, core::EntityType::ConfidentialMarker, core::DetectorKind::Context});
    }
    const auto spans = sentences(view);
    if (spans.empty()) {
        return;
    }
    const auto sentence_of = [&](std::uint32_t unit) {
        const auto it = std::ranges::upper_bound(spans, unit, {}, &SentenceSpan::first_unit);
        return static_cast<std::size_t>(it - spans.begin()) - 1;
    };
    std::vector<bool> marked(spans.size(), false);
    std::vector<bool> subject(spans.size(), false);
    for (const auto& hit : markers.find(view)) {
        marked[sentence_of(hit.first_unit)] = true;
    }
    for (const auto& hit : subjects.find(view)) {
        subject[sentence_of(hit.first_unit)] = true;
    }
    (void)block_sentence_pairs(spans, text, marked, subject, core::EntityType::ConfidentialMatter, out);
}

}  // namespace prompt_airlock::detect::rules
