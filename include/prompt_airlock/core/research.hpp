#pragma once

namespace prompt_airlock::core {

// 연구 평가(Phase 11)와 시험에서만 쓰는 열쇠. 보호 없음 전략과 연구용 정책을 만들 때 필요하다.
// 만드는 함수는 PA_CORE_RESEARCH 가 정의된 빌드에서만 보이고, 정의는 prompt_airlock_core_research
// 라이브러리에만 있다. 운영 빌드는 선언을 볼 수 없고, 직접 선언해도 링크되지 않는다.
class ResearchOnly {
    ResearchOnly() noexcept = default;
    friend ResearchOnly make_research_only() noexcept;
};

#if defined(PA_CORE_RESEARCH)
[[nodiscard]] ResearchOnly make_research_only() noexcept;
#endif

}  // namespace prompt_airlock::core
