// 원문 상자는 복사할 수 없다. 넘겨주기(move)만 된다.
#include "prompt_airlock/core/sensitive.hpp"

#include <utility>

namespace pc = prompt_airlock::core;

std::size_t probe(pc::SensitiveText& original) {
#if PA_CF_OK
    const pc::SensitiveText taken = std::move(original);
#else
    const pc::SensitiveText taken = original;
#endif
    return taken.size();
}
