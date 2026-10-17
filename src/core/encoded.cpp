#include "prompt_airlock/core/encoded.hpp"

#include <utility>
#include <vector>

namespace prompt_airlock::core {

std::expected<void, Rejection> judge_encoded(std::span<const EncodedFinding> findings) {
    EntityTypeSet targets;
    std::vector<AuditFinding> with_targets;
    std::vector<AuditFinding> opaque;
    for (const auto& finding : findings) {
        const EncodedLocation location{finding.segment, finding.source, finding.kind};
        if (!finding.targets.empty()) {
            targets.merge(finding.targets);
            with_targets.emplace_back(location);
        } else if ((!finding.decoded_is_text || finding.still_encoded) &&
                   finding.source.size() >= opaque_blob_min_bytes) {
            opaque.emplace_back(location);
        }
    }
    if (!with_targets.empty()) {
        return std::unexpected(Rejection::with_findings(ReasonCode::EncodedTarget, targets, std::move(with_targets)));
    }
    if (!opaque.empty()) {
        return std::unexpected(Rejection::with_findings(ReasonCode::OpaqueEncodedBlob, {}, std::move(opaque)));
    }
    return {};
}

}  // namespace prompt_airlock::core
