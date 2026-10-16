// 탐지 결과는 텍스트와 대조하는 make 로만 만든다.
#include "prompt_airlock/core/entity.hpp"

#include <string_view>

namespace pc = prompt_airlock::core;

bool probe(std::string_view text, pc::ByteSpan span) {
#if PA_CF_OK
    const auto entity = pc::EntitySpan::make(text, pc::SegmentIndex{0}, span, pc::EntityType::Person, pc::DetectorKind::Ner);
    return entity.has_value();
#else
    const pc::EntitySpan entity{pc::SegmentIndex{0}, span, pc::EntityType::Person, pc::DetectorKind::Ner};
    return text.size() > entity.span().size();
#endif
}
