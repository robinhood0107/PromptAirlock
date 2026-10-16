// 검증 완료 질문은 열쇠 없이 직접 만들 수 없다(잔여 검사를 건너뛸 수 없다).
#include "prompt_airlock/core/prompt.hpp"

#include <utility>

namespace pc = prompt_airlock::core;

std::size_t probe(pc::ProtectedPrompt& protected_prompt, pc::VerifiedPrompt& verified) {
#if PA_CF_OK
    const pc::VerifiedPrompt made{std::move(verified)};
#else
    const pc::VerifiedPrompt made{std::move(protected_prompt)};
#endif
    return made.document().message_count() + protected_prompt.replacements().size();
}
