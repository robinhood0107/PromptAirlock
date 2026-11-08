#include "prompt_airlock/core/residual.hpp"

#include <algorithm>
#include <utility>

#include "prompt_airlock/core/token.hpp"
#include "prompt_airlock/core/utf8.hpp"
#include "state_access.hpp"

namespace prompt_airlock::core {
namespace {

[[nodiscard]] bool span_fits(std::span<const Segment> segments, SegmentIndex segment, ByteSpan span) noexcept {
    return segment.value() < segments.size() && check_span(segments[segment.value()].text(), span).has_value();
}

}  // namespace

PromptDocument residual_scan_document(const ProtectedPrompt& prompt) {
    const auto& document = prompt.document();
    const auto segments = document.segments();
    std::vector<std::string> texts;
    texts.reserve(segments.size());
    for (const auto& segment : segments) texts.emplace_back(segment.text());
    for (const auto& r : prompt.replacements()) {
        if (r.segment.value() >= texts.size() || !span_fits(segments, r.segment, r.span)) continue;
        auto& text = texts[r.segment.value()];
        const auto view = std::string_view(text).substr(r.span.begin().value(), r.span.end().value() - r.span.begin().value());
        if (!parse_token(view)) continue;  // 차단 표지는 무작위 글자가 없다.
        const auto random_end = r.span.end().value() - token_close.size();
        std::fill_n(text.begin() + static_cast<std::ptrdiff_t>(random_end - token_random_length), token_random_length, '0');
    }
    std::vector<Segment> copies;
    copies.reserve(segments.size());
    for (std::size_t i = 0; i < segments.size(); ++i) {
        copies.emplace_back(segments[i].source(), SensitiveText(std::move(texts[i])));
    }
    std::vector<ContentForm> forms;
    for (std::uint32_t m = 0; m < document.message_count(); ++m) forms.push_back(document.content_form(m));
    return PromptDocument(detail::StateAccess::key<PromptDocument>(), std::move(copies), std::move(forms), document.kind());
}

std::expected<VerifiedPrompt, Rejection> verify_residual(ProtectedPrompt prompt, const ResidualReport& report) {
    if (report.entities.size() > max_entities) {
        return std::unexpected(Rejection::of(ReasonCode::TooManyEntities));
    }
    const auto segments = prompt.document().segments();
    for (const auto& entity : report.entities) {
        if (!span_fits(segments, entity.segment(), entity.span())) {
            return std::unexpected(Rejection::from_error(ResidualError::InvalidSpan));
        }
    }
    for (const auto& finding : report.encoded) {
        if (!span_fits(segments, finding.segment, finding.source)) {
            return std::unexpected(Rejection::from_error(ResidualError::InvalidSpan));
        }
    }

    const auto replacements = prompt.replacements();
    EntityTypeSet left;
    std::vector<AuditFinding> findings;
    for (const auto& entity : report.entities) {
        const bool inside_replacement = std::any_of(replacements.begin(), replacements.end(), [&](const Replacement& r) {
            return r.segment == entity.segment() && r.span.contains(entity.span());
        });
        if (!inside_replacement && default_action(entity.type()) != Action::Pass) {
            left.insert(entity.type());
            findings.emplace_back(EntityFinding{entity.segment(), entity.span(), entity.type(), entity.detector()});
        }
    }
    if (!findings.empty()) {
        return std::unexpected(Rejection::with_findings(ReasonCode::ResidualFound, left, std::move(findings)));
    }
    if (const auto encoded = judge_encoded(report.encoded); !encoded) {
        return std::unexpected(encoded.error());
    }
    return VerifiedPrompt(detail::StateAccess::key<VerifiedPrompt>(), std::move(prompt));
}

}  // namespace prompt_airlock::core
