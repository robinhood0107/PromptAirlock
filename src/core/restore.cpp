#include "prompt_airlock/core/restore.hpp"

#include <string>

#include "prompt_airlock/core/link_context.hpp"
#include "prompt_airlock/core/utf8.hpp"
#include "state_access.hpp"

namespace prompt_airlock::core {

std::expected<CheckedResponse, Rejection> check_response(SensitiveText response,
                                                         std::span<const EntitySpan> response_findings) {
    const auto text = response.view();
    if (const auto valid = validate_utf8(text); !valid) {
        return std::unexpected(Rejection::from_error(valid.error()));
    }
    EntityTypeSet blocked;
    std::vector<AuditFinding> findings;
    for (const auto& entity : response_findings) {
        if (entity.segment().value() != 0 || !check_span(text, entity.span())) {
            return std::unexpected(Rejection::from_error(DetectError::InvalidSpan));
        }
        if (default_action(entity.type()) == Action::Block) {
            blocked.insert(entity.type());
            findings.emplace_back(EntityFinding{entity.segment(), entity.span(), entity.type(), entity.detector()});
        }
    }
    if (!findings.empty()) {
        return std::unexpected(Rejection::with_findings(ReasonCode::ResponseBlockedValue, blocked, std::move(findings)));
    }
    return CheckedResponse(detail::StateAccess::key<CheckedResponse>(), std::move(response));
}

std::expected<RestorePlan, Rejection> plan_restore(const CheckedResponse& response) {
    const auto text = response.text();
    auto occurrences = scan_tokens(text);
    if (const auto links = check_link_contexts(text, occurrences); !links) {
        return std::unexpected(links.error());
    }
    return RestorePlan{std::move(occurrences), text.size()};
}

namespace detail {

bool plan_matches(std::string_view response, const RestorePlan& plan) noexcept {
    if (plan.response_bytes != response.size()) {
        return false;
    }
    std::size_t previous_end = 0;
    for (const auto& occurrence : plan.occurrences) {
        const auto span = occurrence.span;
        if (span.begin().value() < previous_end || span.end().value() > response.size() ||
            response.substr(span.begin().value(), span.size()) != occurrence.token.text()) {
            return false;
        }
        previous_end = span.end().value();
    }
    return true;
}

SensitiveText splice_restored(std::string_view response, const RestorePlan& plan, std::span<const SensitiveText> values,
                              std::span<const std::size_t> value_index) {
    std::size_t size = response.size();
    for (std::size_t i = 0; i < plan.occurrences.size(); ++i) {
        size = size - plan.occurrences[i].span.size() + values[value_index[i]].size();
    }
    std::string out;
    out.reserve(size);
    std::size_t copied = 0;
    for (std::size_t i = 0; i < plan.occurrences.size(); ++i) {
        const auto span = plan.occurrences[i].span;
        out.append(response.substr(copied, span.begin().value() - copied));
        out.append(values[value_index[i]].view());
        copied = span.end().value();
    }
    out.append(response.substr(copied));
    return SensitiveText(std::move(out));
}

}  // namespace detail

}  // namespace prompt_airlock::core
