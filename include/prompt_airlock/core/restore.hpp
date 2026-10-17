#pragma once

#include <concepts>
#include <cstddef>
#include <expected>
#include <map>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "prompt_airlock/core/detail/attributes.hpp"
#include "prompt_airlock/core/detail/state_key.hpp"
#include "prompt_airlock/core/entity.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/reason.hpp"
#include "prompt_airlock/core/sensitive.hpp"
#include "prompt_airlock/core/token.hpp"

namespace prompt_airlock::core {

// 응답 처리 순서(ADR 0017 7번)를 타입으로 강제한다: 응답 검사 → token 찾기 → 위치 판정 → 복원.

// 응답 검사를 통과한 응답. 원문 응답(복원 전)을 소유한다.
class CheckedResponse {
public:
    CheckedResponse(detail::StateKey<CheckedResponse>, SensitiveText text) noexcept : text_(std::move(text)) {}

    [[nodiscard]] std::string_view text() const& noexcept PA_LIFETIMEBOUND { return text_.view(); }
    std::string_view text() const&& = delete;

private:
    SensitiveText text_;
};

// 응답을 다시 탐지한 결과(segment 0, 응답 텍스트 기준 위치)로 응답을 검사한다.
// UTF-8 이 아니면 InvalidText, 위치가 맞지 않으면 DetectorUnavailable,
// 차단 종류의 값이 응답에 나타나면 ResponseBlockedValue.
[[nodiscard]] std::expected<CheckedResponse, Rejection> check_response(SensitiveText response,
                                                                      std::span<const EntitySpan> response_findings);

// 복원할 token 들과 그것을 찾은 응답의 길이.
struct RestorePlan {
    std::vector<TokenOccurrence> occurrences;
    std::size_t response_bytes = 0;
};

// token 을 찾고 위치를 판정한다. 링크 문맥 token 이 하나라도 있으면 ResponseTokenInLink.
// 모양이 조금이라도 다른 token 은 token 이 아니므로 바꾸지 않고 그대로 둔다(추측 복원 금지).
[[nodiscard]] std::expected<RestorePlan, Rejection> plan_restore(const CheckedResponse& response);

// 원래 값 복원기. 범위(scope)는 복원기 객체가 갖고, 다른 범위의 token 은 TokenNotFound 다.
template <class R>
concept TokenResolver = requires(R& resolver, const Token& token) {
    { resolver.resolve(token) } -> std::same_as<std::expected<SensitiveText, RestoreError>>;
};

namespace detail {
// plan 이 이 응답에서 만든 것인지(길이, 각 위치의 byte 가 token 과 같은지).
[[nodiscard]] bool plan_matches(std::string_view response, const RestorePlan& plan) noexcept;
// token 자리마다 values[value_index[i]] 를 원래 byte 그대로 끼워 넣는다.
[[nodiscard]] SensitiveText splice_restored(std::string_view response, const RestorePlan& plan,
                                            std::span<const SensitiveText> values,
                                            std::span<const std::size_t> value_index);
}  // namespace detail

// 같은 범위에서 발급한 token 과 정확히 같을 때만 복원한다. 하나라도 못 풀면 응답 전체를 거절한다.
// 서로 다른 token 마다 복원기를 한 번만 부른다.
template <TokenResolver R>
[[nodiscard]] std::expected<SensitiveText, Rejection> apply_restore(CheckedResponse response, const RestorePlan& plan,
                                                                   R& resolver) {
    const auto text = response.text();
    if (!detail::plan_matches(text, plan)) {
        return std::unexpected(Rejection::from_error(RestoreError::PlanMismatch));
    }
    std::map<std::string_view, std::size_t> index_of;
    std::vector<SensitiveText> values;
    std::vector<std::size_t> value_index;
    value_index.reserve(plan.occurrences.size());
    for (const auto& occurrence : plan.occurrences) {
        const auto [found, inserted] = index_of.try_emplace(occurrence.token.text(), values.size());
        if (inserted) {
            auto value = resolver.resolve(occurrence.token);
            if (!value) {
                return std::unexpected(Rejection::from_error(value.error()));
            }
            values.push_back(std::move(*value));
        }
        value_index.push_back(found->second);
    }
    return detail::splice_restored(text, plan, values, value_index);
}

}  // namespace prompt_airlock::core
