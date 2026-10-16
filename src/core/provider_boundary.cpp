#include "prompt_airlock/core/provider_boundary.hpp"

#include <utility>
#include <variant>

#include "state_access.hpp"

namespace prompt_airlock::core {

ProviderRequest::ProviderRequest(detail::StateKey<ProviderRequest>, std::vector<ProviderMessage> messages,
                                 std::vector<SensitiveText> stop, RequestParams params) noexcept
    : messages_(std::move(messages)), stop_(std::move(stop)), params_(params) {}

std::expected<ProviderRequest, Rejection> make_provider_request(const VerifiedPrompt& prompt) {
    const auto& document = prompt.document();
    if (document.message_count() == 0 || document.segments().empty()) {
        return std::unexpected(Rejection::of(ReasonCode::InternalError));
    }
    std::vector<ProviderMessage> messages;
    messages.reserve(document.message_count());
    std::vector<SensitiveText> stop;
    for (const auto& segment : document.segments()) {
        const auto source = segment.source();
        if (const auto* message = std::get_if<MessageSource>(&source)) {
            // 묶음은 메시지 순서대로 part 를 담는다. 어긋나면 문서 불변식이 깨진 것이다.
            if (message->message == messages.size()) {
                messages.push_back(ProviderMessage{message->role, document.content_form(message->message), {}});
            } else if (message->message + 1 != messages.size()) {
                return std::unexpected(Rejection::of(ReasonCode::InternalError));
            }
            messages.back().parts.push_back(SensitiveText::copy_of(segment.text()));
        } else {
            stop.push_back(SensitiveText::copy_of(segment.text()));
        }
    }
    return ProviderRequest(detail::StateAccess::key<ProviderRequest>(), std::move(messages), std::move(stop),
                           prompt.params());
}

}  // namespace prompt_airlock::core
