#include "prompt_airlock/detect/detectors.hpp"

#include <algorithm>
#include <iterator>
#include <optional>
#include <string>

#include "data/account_context_terms.hpp"
#include "data/confidential_terms.hpp"
#include "data/credential_markers.hpp"
#include "data/institution_labels.hpp"
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

// 다른 보기에서 찾은 원문 구간을 이 보기의 글자로 덮는다. 경계가 어긋나면 넓게 잡아 치환이 모자라지 않게 한다.
[[nodiscard]] std::optional<rules::Hit> cover(const DetectionView& view, core::ByteSpan span, core::EntityType type,
                                              core::DetectorKind kind) {
    const auto& u = view.units;
    const auto first = std::ranges::partition_point(u, [&](const auto& x) { return x.source.end() <= span.begin(); });
    const auto after = std::ranges::partition_point(u, [&](const auto& x) { return x.source.begin() < span.end(); });
    if (first >= after) {
        return std::nullopt;
    }
    return rules::Hit{static_cast<std::uint32_t>(first - u.begin()), static_cast<std::uint32_t>(after - u.begin() - 1),
                      type, kind};
}

[[nodiscard]] std::u32string chars_of(const DetectionView& view) {
    std::u32string chars;
    chars.reserve(view.units.size());
    for (const auto& unit : view.units) {
        chars.push_back(unit.value);
    }
    return chars;
}

// 설정에서 온 단어를 보기와 같은 정규화로 바꾸고 단어 안 공백을 뺀다. 같은 글자로 비교하려면 필요하다.
[[nodiscard]] std::expected<std::vector<std::u32string>, core::InputError> normalize_terms(
    std::span<const std::string_view> terms) {
    std::vector<std::u32string> normalized;
    normalized.reserve(terms.size());
    for (const auto term : terms) {
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
    return normalized;
}

// 기관이 더한 말(UTF-8) + 늘 켜는 말 + 고른 업종의 말(모두 이미 NFKC)을 한 일치기로. 겹치는 말은 하나만 둔다.
[[nodiscard]] std::expected<TermMatcher, core::InputError> policy_matcher(
    const std::vector<std::string>& added, std::span<const std::u32string_view> always,
    std::span<const Industry> industries, std::span<const std::u32string_view> (*per_industry)(Industry) noexcept) {
    const std::vector<std::string_view> raw(added.begin(), added.end());
    const auto normalized = normalize_terms(raw);
    if (!normalized) {
        return std::unexpected(normalized.error());
    }
    std::vector<std::u32string_view> views(normalized->begin(), normalized->end());
    views.insert(views.end(), always.begin(), always.end());
    for (const auto industry : industries) {
        const auto built_in = per_industry(industry);
        views.insert(views.end(), built_in.begin(), built_in.end());
    }
    std::ranges::sort(views);
    const auto [first, last] = std::ranges::unique(views);
    views.erase(first, last);
    return TermMatcher::make(views);
}

}  // namespace

Detectors::Detectors(TermMatcher internal_terms, TermMatcher institution_labels, std::vector<IdFormat> id_formats,
                     TermMatcher confidential_markers, TermMatcher confidential_subjects,
                     std::shared_ptr<const NerScanner> ner)
    : internal_terms_(std::move(internal_terms)),
      institution_labels_(std::move(institution_labels)),
      id_formats_(std::move(id_formats)),
      confidential_markers_(std::move(confidential_markers)),
      confidential_subjects_(std::move(confidential_subjects)),
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
                                                         std::shared_ptr<const NerScanner> ner,
                                                         const InstitutionPolicy& policy) {
    auto terms = normalize_terms(internal_terms);
    if (!terms) {
        return std::unexpected(terms.error());
    }
    auto labels = policy_matcher(policy.id_labels, {}, policy.industries, data::institution_labels);
    auto markers = policy_matcher(policy.confidential_markers, data::confidential_markers, {}, nullptr);
    auto subjects = policy_matcher(policy.confidential_subjects, {}, policy.industries, data::confidential_subjects);
    if (!labels || !markers || !subjects) {
        return std::unexpected(!labels ? labels.error() : !markers ? markers.error() : subjects.error());
    }
    const std::vector<std::u32string_view> term_views(terms->begin(), terms->end());
    return Detectors(TermMatcher::make(term_views), std::move(*labels), policy.id_formats, std::move(*markers),
                     std::move(*subjects), std::move(ner));
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
    const auto chars = chars_of(*view);

    std::vector<rules::Hit> hits;
    const auto runs = digit_runs(*view);
    rules::find_identifiers(runs, chars, hits);
    rules::find_network(chars, hits);
    rules::find_secrets(chars, hits);
    rules::find_accounts(runs, chars, account_context_, *view, hits);
    // 숫자 사이에서 줄이 끊긴 번호(결정 #238): 하이픈 없는 줄바꿈도 이은 묶음에서 다시 찾되, 줄을 넘는 번호는
    // 그 종류의 단서 낱말("주민", "전화", "카드" …) 뒤에 올 때만 받는다. 표의 날짜가 이어지지 않게 한다(#236).
    if (chars.find(U'\n') != std::u32string::npos) {
        std::vector<rules::Hit> wrapped;
        rules::find_identifiers(digit_runs(*view, true), chars, wrapped);
        for (const auto& h : wrapped) {
            const auto span = std::u32string_view(chars).substr(h.first, h.last - h.first + 1);
            if (span.find(U'\n') != std::u32string_view::npos && rules::has_wrapped_cue(chars, h)) {
                hits.push_back(h);
            }
        }
    }
    // LaTeX·Typst 표기(\text{-}, {-}, \,, $, 사용자 정의 명령, #sym.dash, #[-])로 끊은 번호·이메일은 표기를 걷어 낸
    // 보기에서 한 번 더 찾는다(결정 #235, #238). 계좌는 문맥어와 통화 기호($ 는 금액)에 기대므로 이 보기에서 돌리지
    // 않는다. % 는 보통 글에 흔해 홀로는 부르지 않는다.
    if (text.find_first_of("\\${}#[") != std::string_view::npos) {
        const auto plain = make_view(text, ViewKind::WithoutLatex);
        if (!plain) {
            return std::unexpected(plain.error());
        }
        const auto plain_chars = chars_of(*plain);
        std::vector<rules::Hit> found;
        rules::find_identifiers(digit_runs(*plain), plain_chars, found);
        rules::find_network(plain_chars, found);
        for (const auto& h : found) {
            if (const auto c = cover(*view, source_span(*plain, h.first, h.last), h.type, h.kind)) {
                hits.push_back(*c);
            }
        }
    }
    rules::find_credentials(chars, secret_markers_, user_markers_, account_markers_, *view, hits);
    for (const auto& hit : internal_terms_.find(*view)) {
        hits.push_back({hit.first_unit, hit.last_unit, core::EntityType::InternalTerm, core::DetectorKind::InternalTerm});
    }
    rules::find_organizations(*view, chars, hits);
    rules::find_institution_ids(*view, chars, institution_labels_, id_formats_, hits);
    rules::find_confidential(*view, chars, confidential_markers_, confidential_subjects_, hits);
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
