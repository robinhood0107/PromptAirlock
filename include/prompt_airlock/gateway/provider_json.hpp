// provider 로 보내는 요청 본문(ADR 0017). 검증을 마친 요청과 고정 모델 별칭만으로 새로 만든다.
// 클라이언트가 보낸 model, 보관·상태 저장 플래그, 헤더는 들어갈 자리가 없다.
#pragma once

#include <string>
#include <string_view>

#include "prompt_airlock/core/provider_boundary.hpp"

namespace prompt_airlock::gateway {

[[nodiscard]] std::string provider_request_body(const core::ProviderRequest& request, std::string_view model_alias);

}  // namespace prompt_airlock::gateway
