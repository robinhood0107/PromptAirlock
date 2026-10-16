#include "prompt_airlock/core/prompt.hpp"

#include <utility>

namespace prompt_airlock::core {

RawPrompt RawPrompt::create(PromptDocument document, RequestParams params, OpenGrade grade) noexcept {
    return RawPrompt(std::move(document), params, grade);
}

RawPrompt::RawPrompt(PromptDocument document, RequestParams params, OpenGrade grade) noexcept
    : document_(std::move(document)), params_(params), grade_(grade) {}

PolicyCheckedPrompt::PolicyCheckedPrompt(detail::StateKey<PolicyCheckedPrompt>, RawPrompt raw,
                                         std::vector<MergedEntity> entities) noexcept
    : raw_(std::move(raw)), entities_(std::move(entities)) {}

ProtectedPrompt::ProtectedPrompt(detail::StateKey<ProtectedPrompt>, PromptDocument protected_document,
                                 RequestParams params, OpenGrade grade, std::vector<Replacement> replacements) noexcept
    : document_(std::move(protected_document)),
      params_(params),
      grade_(grade),
      replacements_(std::move(replacements)) {}

VerifiedPrompt::VerifiedPrompt(detail::StateKey<VerifiedPrompt>, ProtectedPrompt prompt) noexcept
    : prompt_(std::move(prompt)) {}

}  // namespace prompt_airlock::core
