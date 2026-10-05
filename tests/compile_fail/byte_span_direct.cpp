// 바이트 구간은 검사하는 make 로만 만든다. 생성자를 직접 부를 수 없다.
#include "prompt_airlock/core/offset.hpp"

namespace pc = prompt_airlock::core;

std::size_t probe() {
#if PA_CF_OK
    const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{0}, pc::Utf8ByteOffset{1});
#else
    const pc::ByteSpan span{pc::Utf8ByteOffset{1}, pc::Utf8ByteOffset{0}};
#endif
    return span.size();
}
