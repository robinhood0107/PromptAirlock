// provider 응답 읽기와 클라이언트 응답 만들기(ADR 0017, 0020).
// 첫 choice 의 role·content·finish_reason 과 usage 만 읽고, 나머지는 버린다. 클라이언트 응답은 새로 만든다.
#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

#include "prompt_airlock/core/sensitive.hpp"

namespace prompt_airlock::gateway {

struct Usage {
    std::int64_t prompt_tokens = 0;
    std::int64_t completion_tokens = 0;
    std::int64_t total_tokens = 0;
};

struct ProviderAnswer {
    core::SensitiveText content;
    std::string finish_reason;
    std::optional<Usage> usage;
};

enum class AnswerError : std::uint8_t {
    Malformed,  // JSON 오류, 중복 키, 깊이 초과, content 없음, 역할이 다름
    Forbidden,  // tool_calls·function_call·audio·images·logprobs 가 값을 가짐
};

[[nodiscard]] std::expected<ProviderAnswer, AnswerError> parse_provider_answer(std::string_view body);

// id 는 게이트웨이 요청 ID, model 은 고정 별칭이다. provider 의 id·model·그 밖의 필드는 들어가지 않는다.
[[nodiscard]] std::string client_response_body(std::string_view id, std::int64_t created, std::string_view model_alias,
                                               std::string_view content, std::string_view finish_reason,
                                               const std::optional<Usage>& usage);

}  // namespace prompt_airlock::gateway
