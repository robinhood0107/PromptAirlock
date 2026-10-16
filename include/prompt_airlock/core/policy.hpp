#pragma once

#include <cstddef>
#include <expected>
#include <span>

#include "prompt_airlock/core/entity.hpp"
#include "prompt_airlock/core/prompt.hpp"
#include "prompt_airlock/core/reason.hpp"
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

// 원문 질문을 정책으로 검사한다. 순서: 탐지 결과가 max_entities 를 넘으면 TooManyEntities,
// 위치를 문서와 다시 대조해 맞지 않으면 DetectorUnavailable(detector 를 믿지 않는다),
// 차단 종류가 하나라도 있으면 EntityBlocked(사용자에게는 종류만, 감사에는 위치). 통과하면 겹친 결과를 합쳐 넘긴다.
// raw 는 값으로 받으므로 거절되면 이 함수 안에서 지워진다.
[[nodiscard]] std::expected<PolicyCheckedPrompt, Rejection> check_policy(RawPrompt raw,
                                                                         std::span<const EntitySpan> detected,
                                                                         const Policy& policy);

}  // namespace prompt_airlock::core
