// 바이트 구간은 글자 위치로 만들 수 없다.
#include "prompt_airlock/core/offset.hpp"

namespace pc = prompt_airlock::core;

bool probe() {
#if PA_CF_OK
    return pc::ByteSpan::make(pc::Utf8ByteOffset{0}, pc::Utf8ByteOffset{1}).has_value();
#else
    return pc::ByteSpan::make(pc::CodepointOffset{0}, pc::CodepointOffset{1}).has_value();
#endif
}
