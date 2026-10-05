// UTF-8 검증·디코드·offset 변환이 아무 바이트에도 죽지 않고 서로 맞는지 본다.
#include "prompt_airlock/core/utf8.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace pc = prompt_airlock::core;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    const auto valid = pc::validate_utf8(text);
    const auto decoded = pc::decode_utf8(text);
    if (valid.has_value() != decoded.has_value()) {
        __builtin_trap();
    }
    for (std::size_t i = 0; i <= size + 1; ++i) {
        (void)pc::is_codepoint_boundary(text, pc::Utf8ByteOffset{i});
    }
    if (!decoded) {
        return 0;
    }
    std::size_t at = 0;
    for (const auto& unit : *decoded) {
        if (unit.source.begin().value() != at || unit.source.size() == 0 || unit.source.size() > 4) {
            __builtin_trap();
        }
        at = unit.source.end().value();
    }
    if (at != size) {
        __builtin_trap();
    }
    // offset 변환은 선형이므로 앞쪽 일부만 왕복 확인한다.
    const auto checked = std::min<std::size_t>(decoded->size(), 64);
    for (std::size_t i = 0; i < checked; ++i) {
        const auto begin = (*decoded)[i].source.begin();
        const auto byte = pc::to_byte_offset(text, pc::CodepointOffset{i});
        const auto codepoint = pc::to_codepoint_offset(text, begin);
        if (!byte || *byte != begin || !codepoint || codepoint->value() != i) {
            __builtin_trap();
        }
    }
    return 0;
}
