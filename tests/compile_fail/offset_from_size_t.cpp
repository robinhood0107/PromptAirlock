// 숫자에서 위치 타입으로 자동 변환되지 않는다.
#include "prompt_airlock/core/offset.hpp"

namespace pc = prompt_airlock::core;

pc::Utf8ByteOffset probe() {
#if PA_CF_OK
    pc::Utf8ByteOffset at{3};
#else
    pc::Utf8ByteOffset at = 3;
#endif
    return at;
}
