// 검증 완료 질문은 복사할 수 없다. 넘겨주기만 된다.
#include "prompt_airlock/core/prompt.hpp"

#include <utility>

namespace pc = prompt_airlock::core;

std::size_t probe(pc::VerifiedPrompt& verified) {
#if PA_CF_OK
    const pc::VerifiedPrompt taken = std::move(verified);
#else
    const pc::VerifiedPrompt taken = verified;
#endif
    return taken.document().message_count();
}
