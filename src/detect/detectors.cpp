#include "prompt_airlock/detect/detectors.hpp"

#include <algorithm>
#include <iterator>
#include <optional>
#include <string>

#include "data/account_context_terms.hpp"
#include "data/credential_markers.hpp"
#include "data/personal_markers.hpp"
#include "data/sensitive_category_terms.hpp"
#include "prompt_airlock/detect/encoded.hpp"
#include "prompt_airlock/core/types.hpp"
#include "rules.hpp"

namespace prompt_airlock::detect {
namespace {

// NER 결과(원문 byte)를 보기의 글자 구간으로 되돌린다. 구간 끝이 보기 글자 경계와 맞지 않으면 nullopt.
[[nodiscard]] std::optional<rules::Hit> to_hit(const DetectionView& view, const core::EntitySpan& entity) {
    // 보기 글자는 원문 순서대로라 원문 시작 위치로 정렬돼 있다. 정규화로 갈라진 글자들은 같은 원문 구간을 가진다.
    const auto begin = entity.span().begin();
    const auto end = entity.span().end();
    const auto source_begin = [](const core::DecodedCodepoint& u) { return u.source.begin(); };
    const auto first = std::ranges::lower_bound(view.units, begin, {}, source_begin);
    const auto after = std::ranges::lower_bound(view.units, end, {}, source_begin);
    if (first == view.units.end() || first->source.begin() != begin || after == first ||
        std::prev(after)->source.end() != end) {
        return std::nullopt;
    }
    const auto last = std::prev(after);
    return rules::Hit{static_cast<std::uint32_t>(first - view.units.begin()),
                      static_cast<std::uint32_t>(last - view.units.begin()), entity.type(), entity.detector()};
}

}  // namespace

Detectors::Detectors(TermMatcher internal_terms, std::shared_ptr<const NerScanner> ner)
    : internal_terms_(std::move(internal_terms)),
      ner_(std::move(ner)),
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

std::expected<Detectors, core::InputError> Detectors::make(std::span<const std::string_view> internal_terms,
                                                         std::shared_ptr<const NerScanner> ner) {
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
    return Detectors(TermMatcher::make(views), std::move(ner));
}

std::expected<std::vector<core::EntitySpan>, core::DetectError> Detectors::detect_segment(
    std::string_view text, core::SegmentIndex segment, std::stop_token stop) const {
    SensitiveTally ignored;
    return scan(text, segment, ignored, stop);
}

std::expected<std::vector<core::EntitySpan>, core::DetectError> Detectors::scan(std::string_view text,
                                                                             core::SegmentIndex segment,
                                                                             SensitiveTally& tally,
                                                                             std::stop_token stop) const {
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
    rules::find_organizations(*view, chars, hits);
    if (ner_) {
        const auto names = ner_->scan(text, segment, *view, stop);
        if (!names) {
            return std::unexpected(names.error());
        }
        for (const auto& name : *names) {
            const auto hit = to_hit(*view, name);
            if (!hit) {
                return std::unexpected(core::DetectError::InvalidSpan);
            }
            hits.push_back(*hit);
        }
    }
    // 민감정보는 앞의 결과(식별 정보, NER 사람 이름 포함)를 개인 표지로 쓰므로 마지막에 돈다.
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

std::expected<std::vector<core::EncodedFinding>, core::DetectError> Detectors::scan_encoded(
    std::string_view text, core::SegmentIndex segment, std::stop_token stop) const {
    const auto candidates = encoded_candidates(text);
    if (candidates.size() > max_encoded_candidates) {
        return std::unexpected(core::DetectError::Overloaded);
    }
    // 푼 텍스트를 같은 탐지기로 보고 찾은 종류를 targets 에 모은다.
    const auto collect = [&](std::string_view decoded,
                             core::EntityTypeSet& targets) -> std::expected<void, core::DetectError> {
        SensitiveTally ignored;
        const auto found = scan(decoded, segment, ignored, stop);
        if (!found) {
            return std::unexpected(found.error());
        }
        for (const auto& e : *found) {
            targets.insert(e.type());
        }
        return {};
    };
    // 후보 하나가 텍스트의 절반 이상을 덮으면 그 텍스트는 여전히 인코딩이다.
    const auto covered_by_blob = [](std::string_view s) {
        return std::ranges::any_of(encoded_candidates(s),
                                   [&](const EncodedCandidate& c) { return c.source.size() * 2 >= s.size(); });
    };
    std::vector<core::EncodedFinding> out;
    out.reserve(candidates.size());
    for (const auto& c : candidates) {
        const auto blob = text.substr(c.source.begin().value(), c.source.size());
        const auto first = decode(blob, c.kind);
        core::EncodedFinding f{segment, c.source, c.kind, *core::DecodeDepth::make(1), first && is_text(*first), false, {}};
        if (f.decoded_is_text) {
            if (auto r = collect(*first, f.targets); !r) {
                return std::unexpected(r.error());
            }
            const std::string_view level1 = *first;
            for (const auto& inner : encoded_candidates(level1)) {
                const auto second = decode(level1.substr(inner.source.begin().value(), inner.source.size()), inner.kind);
                const bool whole = inner.source.size() * 2 >= level1.size();
                if (!second || !is_text(*second)) {
                    // 텍스트 대부분이 텍스트로 풀리지 않는 덩어리면 텍스트가 아닌 것으로 본다.
                    f.decoded_is_text = f.decoded_is_text && !whole;
                    continue;
                }
                f.depth = *core::DecodeDepth::make(2);
                if (auto r = collect(*second, f.targets); !r) {
                    return std::unexpected(r.error());
                }
                f.still_encoded = f.still_encoded || covered_by_blob(*second);
            }
        }
        out.push_back(f);
    }
    return out;
}

std::expected<DocumentDetection, core::DetectError> Detectors::detect(const core::PromptDocument& document,
                                                                  std::stop_token stop) const {
    DocumentDetection result;
    const auto segments = document.segments();
    for (std::uint32_t i = 0; i < segments.size(); ++i) {
        const auto text = segments[i].text();
        if (result.entities.size() <= core::max_entities) {
            auto found = scan(text, core::SegmentIndex{i}, result.sensitive_passed, stop);
            if (!found) {
                return std::unexpected(found.error());
            }
            const auto room = core::max_entities + 1 - result.entities.size();
            const auto take = std::min(room, found->size());
            result.entities.insert(result.entities.end(), found->begin(),
                                   found->begin() + static_cast<std::ptrdiff_t>(take));
        }
        auto encoded = scan_encoded(text, core::SegmentIndex{i}, stop);
        if (!encoded) {
            return std::unexpected(encoded.error());
        }
        if (result.encoded.size() + encoded->size() > max_encoded_candidates) {
            return std::unexpected(core::DetectError::Overloaded);
        }
        result.encoded.insert(result.encoded.end(), encoded->begin(), encoded->end());
    }
    return result;
}

}  // namespace prompt_airlock::detect
