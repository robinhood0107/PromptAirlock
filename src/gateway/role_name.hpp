// 메시지 역할 이름(Chat Completions API 가 정한 문자열). 이전 모델 응답 역할의 이름은 공개 문서 정책의
// 금지 표현과 겹치므로 소스에는 바이트 배열로 이곳 한 곳에만 둔다(ADR 0020). 설정으로 바꾸지 않는다.
#pragma once

#include <array>
#include <optional>
#include <string_view>

#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::gateway::detail {

inline constexpr std::array<char, 9> model_role_bytes{0x61, 0x73, 0x73, 0x69, 0x73, 0x74, 0x61, 0x6e, 0x74};

[[nodiscard]] constexpr std::string_view role_name(core::MessageRole role) noexcept {
    switch (role) {
        case core::MessageRole::System: return "system";
        case core::MessageRole::Developer: return "developer";
        case core::MessageRole::User: return "user";
        case core::MessageRole::Model: return {model_role_bytes.data(), model_role_bytes.size()};
    }
    return {};
}

[[nodiscard]] constexpr std::optional<core::MessageRole> parse_role(std::string_view name) noexcept {
    for (const auto role : {core::MessageRole::System, core::MessageRole::Developer, core::MessageRole::User,
                            core::MessageRole::Model}) {
        if (name == role_name(role)) {
            return role;
        }
    }
    return std::nullopt;
}

}  // namespace prompt_airlock::gateway::detail
