#include "prompt_airlock/core/policy.hpp"

#include <utility>
#include <vector>

#include "prompt_airlock/core/utf8.hpp"
#include "state_access.hpp"

namespace prompt_airlock::core {

std::expected<PolicyCheckedPrompt, Rejection> check_policy(RawPrompt raw, std::span<const EntitySpan> detected,
                                                           const Policy& policy) {
    if (detected.size() > policy.max_entities()) {
        return std::unexpected(Rejection::of(ReasonCode::TooManyEntities));
    }
    const auto segments = raw.document().segments();
    for (const auto& entity : detected) {
        const auto index = entity.segment().value();
        if (index >= segments.size() || !check_span(segments[index].text(), entity.span())) {
            return std::unexpected(Rejection::from_error(DetectError::InvalidSpan));
        }
    }

    EntityTypeSet blocked;
    std::vector<AuditFinding> findings;
    for (const auto& entity : detected) {
        if (policy.action_for(entity.type()) == Action::Block) {
            blocked.insert(entity.type());
            findings.emplace_back(EntityFinding{entity.segment(), entity.span(), entity.type(), entity.detector()});
        }
    }
    if (!blocked.empty()) {
        return std::unexpected(Rejection::with_findings(ReasonCode::EntityBlocked, blocked, std::move(findings)));
    }
    return PolicyCheckedPrompt(detail::StateAccess::key<PolicyCheckedPrompt>(), std::move(raw),
                               merge_entities(detected));
}

}  // namespace prompt_airlock::core
