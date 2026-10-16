#pragma once

#include <cstddef>

#include "prompt_airlock/core/request_params.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// 요청 하나가 처음에 잡는 불변 정책 스냅샷(spec §21). 데이터 멤버가 const 라 대입할 수 없다.
// 17종 처리와 한도는 고정이고(ADR 0015), 기관이 바꿀 수 있는 것은 출력 token 상한뿐이다(ADR 0017).
class Policy {
public:
    [[nodiscard]] static constexpr Policy standard(OutputTokenCap cap = OutputTokenCap::standard()) noexcept {
        return Policy(cap);
    }

    [[nodiscard]] constexpr Action action_for(EntityType type) const noexcept { return default_action(type); }
    [[nodiscard]] constexpr std::size_t max_prompt_bytes() const noexcept { return core::max_prompt_bytes; }
    [[nodiscard]] constexpr std::size_t max_entities() const noexcept { return core::max_entities; }
    [[nodiscard]] constexpr OutputTokenCap output_token_cap() const noexcept { return output_token_cap_; }

private:
    constexpr explicit Policy(OutputTokenCap cap) noexcept : output_token_cap_(cap) {}

    const OutputTokenCap output_token_cap_;
};

}  // namespace prompt_airlock::core
