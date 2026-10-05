#pragma once

#include <cstdint>

namespace prompt_airlock::core {

// 입력 텍스트·위치 검증 실패.
enum class InputError : std::uint8_t {
    InvalidUtf8,
    EmptySpan,
    OffsetOutOfRange,
    NotCodepointBoundary,
    SegmentOutOfRange,
    EmptyDocument,
    EmptyContent,
    TooLarge,
    ValueOutOfRange,
};

}  // namespace prompt_airlock::core
