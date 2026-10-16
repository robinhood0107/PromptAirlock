// 보호 없음 전략은 연구용 열쇠 없이 만들 수 없다(invariant 12).
#include "prompt_airlock/core/strategy.hpp"

namespace pc = prompt_airlock::core;

bool probe() {
#if PA_CF_OK
    const auto strategy = pc::PrivacyStrategy::redaction();
#else
    const auto strategy = pc::PrivacyStrategy::no_protection(pc::ResearchOnly{});
#endif
    return strategy.kind() == pc::PrivacyStrategyKind::NoProtection;
}
