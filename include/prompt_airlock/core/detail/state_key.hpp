#pragma once

namespace prompt_airlock::core::detail {

// 열쇠 공장. 정의는 src/core/state_access.hpp 에만 있어 core 밖에서는 열쇠를 만들 수 없다.
struct StateAccess;

// 단계 타입의 생성자가 요구하는 열쇠(passkey). 정해진 core 함수만 다음 단계를 만들게 한다.
// 같은 프로세스 안에서 일부러 StateAccess 를 다시 정의하는 코드까지는 막지 못한다(실수 방지 장치).
template <class State>
class StateKey {
    friend struct StateAccess;
    constexpr StateKey() noexcept = default;
};

}  // namespace prompt_airlock::core::detail
