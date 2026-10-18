#include "prompt_airlock/detect/detectors.hpp"

#include <algorithm>
#include <string>

#include "data/account_context_terms.hpp"
#include "data/credential_markers.hpp"
#include "data/personal_markers.hpp"
#include "data/sensitive_category_terms.hpp"
#include "prompt_airlock/core/types.hpp"
#include "rules.hpp"

namespace prompt_airlock::detect {

Detectors::Detectors(TermMatcher internal_terms)
    : internal_terms_(std::move(internal_terms)),
      account_context_(TermMatcher::make(data::account_context_terms)),
      secret_markers_(TermMatcher::make(data::secret_markers)),
      user_markers_(TermMatcher::make(data::user_markers)),
      account_markers_(TermMatcher::make(data::account_markers)),
      sensitive_categories_(TermMatcher::make([] {
          std::vector<std::u32string_view> terms;
          for (const auto& t : data::sensitive_terms) {
              terms.push_back(t.term);
          }
          return terms;
      }())),
      honorifics_(TermMatcher::make(data::honorific_suffixes)),
      self_statements_(TermMatcher::make(data::self_statements)) {}

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
    SensitiveTally ignored;
    return scan(text, segment, ignored);
}

std::expected<std::vector<core::EntitySpan>, core::DetectError> Detectors::scan(std::string_view text,
                                                                             core::SegmentIndex segment,
                                                                             SensitiveTally& tally) const {
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
    const auto runs = digit_runs(*view);
    rules::find_identifiers(runs, chars, hits);
    rules::find_network(chars, hits);
    rules::find_secrets(chars, hits);
    rules::find_accounts(runs, chars, account_context_, *view, hits);
    rules::find_credentials(chars, secret_markers_, user_markers_, account_markers_, *view, hits);
    for (const auto& hit : internal_terms_.find(*view)) {
        hits.push_back({hit.first_unit, hit.last_unit, core::EntityType::InternalTerm, core::DetectorKind::InternalTerm});
    }
    // 민감정보는 앞의 결과(식별 정보)를 개인 표지로 쓰므로 마지막에 돈다.
    const std::vector<rules::Hit> identities = hits;
    rules::find_sensitive(*view, chars, {sensitive_categories_, honorifics_, self_statements_}, identities, hits, tally);
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
    for (std::uint32_t i = 0; i < segments.size(); ++i) {
        const auto text = segments[i].text();
        if (result.entities.size() <= core::max_entities) {
            auto found = scan(text, core::SegmentIndex{i}, result.sensitive_passed);
            if (!found) {
                return std::unexpected(found.error());
            }
            const auto room = core::max_entities + 1 - result.entities.size();
            const auto take = std::min(room, found->size());
            result.entities.insert(result.entities.end(), found->begin(),
                                   found->begin() + static_cast<std::ptrdiff_t>(take));
        }
    }
    return result;
}

}  // namespace prompt_airlock::detect
