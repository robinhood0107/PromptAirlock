#include "prompt_airlock/core/residual.hpp"

#include <algorithm>
#include <utility>

#include "prompt_airlock/core/utf8.hpp"
#include "state_access.hpp"

namespace prompt_airlock::core {
namespace {

[[nodiscard]] bool span_fits(std::span<const Segment> segments, SegmentIndex segment, ByteSpan span) noexcept {
    return segment.value() < segments.size() && check_span(segments[segment.value()].text(), span).has_value();
}

}  // namespace

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
