// token 찾기가 아무 바이트에도 죽지 않고, 찾은 것은 모두 정확한 token 이며 겹치지 않는지 본다.
#include "prompt_airlock/core/token.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace pc = prompt_airlock::core;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    std::size_t previous_end = 0;
    for (const auto& occurrence : pc::scan_tokens(text)) {
        const auto span = occurrence.span;
        if (span.begin().value() < previous_end || span.end().value() > size) {
            __builtin_trap();
        }
        const auto parsed = pc::parse_token(text.substr(span.begin().value(), span.size()));
        if (!parsed || *parsed != occurrence.token) {
            __builtin_trap();
        }
        previous_end = span.end().value();
    }
    (void)pc::parse_token(text);
    return 0;
}
