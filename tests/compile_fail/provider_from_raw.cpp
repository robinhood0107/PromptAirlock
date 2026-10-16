// 검증이 끝나지 않은 단계(RawPrompt)로는 외부 요청을 만들 수 없다.
#include "prompt_airlock/core/provider_boundary.hpp"

namespace pc = prompt_airlock::core;

bool probe(const pc::RawPrompt& unchecked, const pc::VerifiedPrompt& verified) {
#if PA_CF_OK
    (void)unchecked;
    return pc::make_provider_request(verified).has_value();
#else
    (void)verified;
    return pc::make_provider_request(unchecked).has_value();
#endif
}
