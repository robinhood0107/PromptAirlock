// 단계 타입의 열쇠는 core 밖에서 만들 수 없다.
#include "prompt_airlock/core/prompt.hpp"

#include <type_traits>

namespace pc = prompt_airlock::core;

bool probe() {
#if PA_CF_OK
    using Key = pc::detail::StateKey<pc::VerifiedPrompt>;
    return std::is_trivially_copyable_v<Key>;
#else
    const pc::detail::StateKey<pc::VerifiedPrompt> key{};
    return std::is_trivially_copyable_v<decltype(key)>;
#endif
}
