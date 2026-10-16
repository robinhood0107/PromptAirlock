#include "prompt_airlock/core/entity.hpp"

#include <utility>

#include "prompt_airlock/core/utf8.hpp"

namespace prompt_airlock::core {

std::expected<EntitySpan, InputError> EntitySpan::make(std::string_view segment_text, SegmentIndex segment,
                                                       ByteSpan span, EntityType type,
                                                       DetectorKind detector) noexcept {
    if (std::to_underlying(type) >= entity_type_count ||
        std::to_underlying(detector) > std::to_underlying(DetectorKind::Ner)) {
        return std::unexpected(InputError::ValueOutOfRange);
    }
    if (const auto checked = check_span(segment_text, span); !checked) {
        return std::unexpected(checked.error());
    }
    return EntitySpan(segment, span, type, detector);
}

}  // namespace prompt_airlock::core
