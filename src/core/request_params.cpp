#include "prompt_airlock/core/request_params.hpp"

#include <algorithm>
#include <cmath>

namespace prompt_airlock::core {
namespace {

[[nodiscard]] bool in_range(std::optional<double> value, double low, double high) noexcept {
    return !value || (std::isfinite(*value) && *value >= low && *value <= high);
}

}  // namespace

std::expected<RequestParams, Rejection> RequestParams::create(const RequestParamsInput& input,
                                                              OutputTokenCap cap) noexcept {
    const auto out_of_range = [] { return std::unexpected(Rejection::of(ReasonCode::ParameterOutOfRange)); };

    if (input.stream.value_or(false)) {
        return std::unexpected(Rejection::of(ReasonCode::StreamNotAllowed));
    }
    if (input.n && *input.n != 1) {
        return out_of_range();
    }
    if (!in_range(input.temperature, 0.0, 2.0) || !in_range(input.top_p, 0.0, 1.0)) {
        return out_of_range();
    }
    // 두 필드가 다르면 사용자가 원한 값을 알 수 없으므로 하나를 조용히 고르지 않는다.
    if (input.max_tokens && input.max_completion_tokens && *input.max_tokens != *input.max_completion_tokens) {
        return out_of_range();
    }
    const auto requested = input.max_tokens ? input.max_tokens : input.max_completion_tokens;
    if (requested && *requested <= 0) {
        return out_of_range();
    }
    const std::uint32_t limit =
        requested ? static_cast<std::uint32_t>(std::min<std::int64_t>(*requested, cap.value())) : cap.value();
    return RequestParams(limit, input.temperature, input.top_p, input.response_format);
}

}  // namespace prompt_airlock::core
