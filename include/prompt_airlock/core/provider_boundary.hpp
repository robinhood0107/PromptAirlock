#pragma once

#include <expected>
#include <span>
#include <vector>

#include "prompt_airlock/core/detail/attributes.hpp"
#include "prompt_airlock/core/detail/state_key.hpp"
#include "prompt_airlock/core/document.hpp"
#include "prompt_airlock/core/prompt.hpp"
#include "prompt_airlock/core/reason.hpp"
#include "prompt_airlock/core/request_params.hpp"
#include "prompt_airlock/core/sensitive.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// provider 로 보낼 메시지 하나. 내용은 검증을 마친 보호 후 텍스트다.
struct ProviderMessage {
    MessageRole role;
    ContentForm form;
    std::vector<SensitiveText> parts;
};

// provider 로 보낼 요청 전체(ADR 0017). 검증된 질문과 파라미터만으로 새로 만든다.
// n, stream, model, 보관·상태 저장 플래그는 담을 자리가 없다. 값은 직렬화(Phase 10)에서 고정한다.
class ProviderRequest {
public:
    ProviderRequest(detail::StateKey<ProviderRequest>, std::vector<ProviderMessage> messages,
                    std::vector<SensitiveText> stop, RequestParams params) noexcept;

    ProviderRequest(const ProviderRequest&) = delete;
    ProviderRequest& operator=(const ProviderRequest&) = delete;
    ProviderRequest(ProviderRequest&&) noexcept = default;
    ProviderRequest& operator=(ProviderRequest&&) noexcept = default;
    ~ProviderRequest() = default;

    [[nodiscard]] std::span<const ProviderMessage> messages() const& noexcept PA_LIFETIMEBOUND { return messages_; }
    std::span<const ProviderMessage> messages() const&& = delete;
    [[nodiscard]] std::span<const SensitiveText> stop() const& noexcept PA_LIFETIMEBOUND { return stop_; }
    std::span<const SensitiveText> stop() const&& = delete;
    [[nodiscard]] const RequestParams& params() const noexcept { return params_; }

private:
    std::vector<ProviderMessage> messages_;
    std::vector<SensitiveText> stop_;
    RequestParams params_;
};

// provider 로 가는 유일한 입구. 검증 완료 단계만 받는다(invariant 1, 2).
// 이미 넘겨져 빈 질문이면 InternalError 로 거절한다(fail closed).
[[nodiscard]] std::expected<ProviderRequest, Rejection> make_provider_request(const VerifiedPrompt& prompt);

}  // namespace prompt_airlock::core
