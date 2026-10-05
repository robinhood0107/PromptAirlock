// 바이트 위치와 글자 위치는 비교할 수 없다.
#include "prompt_airlock/core/offset.hpp"

namespace pc = prompt_airlock::core;

bool probe(pc::Utf8ByteOffset byte, pc::CodepointOffset codepoint) {
#if PA_CF_OK
    return byte == pc::Utf8ByteOffset{codepoint.value()};
#else
    return byte == codepoint;
#endif
}
