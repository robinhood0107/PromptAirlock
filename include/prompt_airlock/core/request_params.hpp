#pragma once

#include <cstdint>
#include <expected>
#include <optional>

#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/reason.hpp"

namespace prompt_airlock::core {

// 외부로 보내는 출력 token 상한(ADR 0017). 기본 4096, 기관이 1~65536 안에서 조절한다.
class OutputTokenCap {
public:
    static constexpr std::uint32_t standard_value = 4096;
    static constexpr std::uint32_t max_value = 65536;

    [[nodiscard]] static constexpr OutputTokenCap standard() noexcept { return OutputTokenCap(standard_value); }
    [[nodiscard]] static constexpr std::expected<OutputTokenCap, InputError> make(std::uint32_t value) noexcept {
        if (value == 0 || value > max_value) {
            return std::unexpected(InputError::ValueOutOfRange);
        }
        return OutputTokenCap(value);
    }
    [[nodiscard]] constexpr std::uint32_t value() const noexcept { return value_; }
    constexpr bool operator==(const OutputTokenCap&) const noexcept = default;

private:
    constexpr explicit OutputTokenCap(std::uint32_t value) noexcept : value_(value) {}
    std::uint32_t value_;
};

enum class ResponseFormat : std::uint8_t { Text, JsonObject };

// JSON 경계(Phase 8)가 채우는 날 값. 없는 필드는 nullopt.
struct RequestParamsInput {
    std::optional<std::int64_t> max_tokens{};
    std::optional<std::int64_t> max_completion_tokens{};
    std::optional<std::int64_t> n{};
    std::optional<double> temperature{};
    std::optional<double> top_p{};
    std::optional<bool> stream{};
    std::optional<ResponseFormat> response_format{};
};

// 범위 검사를 통과한 요청 파라미터. n·stream 은 담지 않는다(항상 1·false 로 보낸다).
class RequestParams {
public:
    // 출력 길이: 없으면 상한, 상한보다 크면 상한으로 줄임, 0 이하나 두 필드 값이 다르면 ParameterOutOfRange.
    // temperature 0~2, top_p 0~1(유한 값), n 은 없거나 1, stream true 는 StreamNotAllowed.
    [[nodiscard]] static std::expected<RequestParams, Rejection> create(const RequestParamsInput& input,
                                                                        OutputTokenCap cap) noexcept;

    [[nodiscard]] constexpr std::uint32_t max_output_tokens() const noexcept { return max_output_tokens_; }
    [[nodiscard]] constexpr std::optional<double> temperature() const noexcept { return temperature_; }
    [[nodiscard]] constexpr std::optional<double> top_p() const noexcept { return top_p_; }
    [[nodiscard]] constexpr std::optional<ResponseFormat> response_format() const noexcept { return response_format_; }

private:
    constexpr RequestParams(std::uint32_t max_output_tokens, std::optional<double> temperature,
                            std::optional<double> top_p, std::optional<ResponseFormat> response_format) noexcept
        : max_output_tokens_(max_output_tokens),
          temperature_(temperature),
          top_p_(top_p),
          response_format_(response_format) {}

    std::uint32_t max_output_tokens_;
    std::optional<double> temperature_;
    std::optional<double> top_p_;
    std::optional<ResponseFormat> response_format_;
};

}  // namespace prompt_airlock::core
