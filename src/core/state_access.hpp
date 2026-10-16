#pragma once

// core 구현 전용 헤더. include/ 에 두지 않는다.
#include "prompt_airlock/core/detail/state_key.hpp"

namespace prompt_airlock::core::detail {

struct StateAccess {
    template <class State>
    [[nodiscard]] static constexpr StateKey<State> key() noexcept {
        return StateKey<State>{};
    }
};

}  // namespace prompt_airlock::core::detail
