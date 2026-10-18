#include "prompt_airlock/detect/detectors.hpp"

#include <algorithm>
#include <string>

#include "prompt_airlock/core/types.hpp"
#include "rules.hpp"

namespace prompt_airlock::detect {

std::expected<Detectors, core::InputError> Detectors::make(std::span<const std::string_view> internal_terms) {
    // 보호어도 보기와 같은 정규화를 거쳐야 같은 글자로 비교된다.
    std::vector<std::u32string> normalized;
    normalized.reserve(internal_terms.size());
    for (const auto term : internal_terms) {
        const auto view = make_view(term);
        if (!view) {
            return std::unexpected(core::InputError::InvalidUtf8);
        }
        std::u32string text;
        for (const auto& unit : view->units) {
            if (!is_term_space(unit.value)) {
                text.push_back(unit.value);
            }
        }
        if (text.empty()) {
            return std::unexpected(core::InputError::EmptyContent);
        }
        normalized.push_back(std::move(text));
    }
    const std::vector<std::u32string_view> views(normalized.begin(), normalized.end());
    return Detectors(TermMatcher::make(views));
}

std::expected<std::vector<core::EntitySpan>, core::DetectError> Detectors::detect_segment(
    std::string_view text, core::SegmentIndex segment) const {
    const auto view = make_view(text);
    if (!view) {
        return std::unexpected(view.error());
    }
    std::u32string chars;
    chars.reserve(view->units.size());
    for (const auto& unit : view->units) {
        chars.push_back(unit.value);
    }

    std::vector<rules::Hit> hits;
    rules::find_identifiers(*view, chars, hits);
    rules::find_network(chars, hits);
    rules::find_secrets(chars, hits);
    for (const auto& hit : internal_terms_.find(*view)) {
        hits.push_back({hit.first_unit, hit.last_unit, core::EntityType::InternalTerm, core::DetectorKind::InternalTerm});
    }
    std::ranges::sort(hits);
    const auto [first, last] = std::ranges::unique(hits);
    hits.erase(first, last);

    std::vector<core::EntitySpan> out;
    out.reserve(std::min(hits.size(), core::max_entities + 1));
    for (const auto& hit : hits) {
        if (out.size() > core::max_entities) {
            break;
        }
        auto entity = core::EntitySpan::make(text, segment, source_span(*view, hit.first, hit.last), hit.type,
                                             hit.kind);
        if (!entity) {
            return std::unexpected(core::DetectError::InvalidSpan);
        }
        out.push_back(*entity);
    }
    return out;
}

std::expected<DocumentDetection, core::DetectError> Detectors::detect(const core::PromptDocument& document) const {
    DocumentDetection result;
    const auto segments = document.segments();
    for (std::uint32_t i = 0; i < segments.size() && result.entities.size() <= core::max_entities; ++i) {
        auto found = detect_segment(segments[i].text(), core::SegmentIndex{i});
        if (!found) {
            return std::unexpected(found.error());
        }
        const auto room = core::max_entities + 1 - result.entities.size();
        const auto take = std::min(room, found->size());
        result.entities.insert(result.entities.end(), found->begin(),
                               found->begin() + static_cast<std::ptrdiff_t>(take));
    }
    return result;
}

}  // namespace prompt_airlock::detect
