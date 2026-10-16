#pragma once

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/detail/attributes.hpp"
#include "prompt_airlock/core/detail/state_key.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// 가명 token 형식 ⟦LABEL_R⟧ (ADR 0008). R 은 Crockford base32 대문자 10자.
inline constexpr std::string_view token_open = "\xE2\x9F\xA6";   // U+27E6
inline constexpr std::string_view token_close = "\xE2\x9F\xA7";  // U+27E7
inline constexpr std::size_t token_random_length = 10;
inline constexpr std::string_view token_alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";  // I, L, O, U 없음

// 모양이 정확한 token. parse_token 만 만든다. 원문 값은 담지 않는다.
class Token {
public:
    Token(detail::StateKey<Token>, std::string text, EntityType label_type) noexcept;

    [[nodiscard]] std::string_view text() const& noexcept PA_LIFETIMEBOUND { return text_; }
    std::string_view text() const&& = delete;
    [[nodiscard]] EntityType label_type() const noexcept { return label_type_; }
    // R 부분(10자).
    [[nodiscard]] std::string_view random_part() const& noexcept PA_LIFETIMEBOUND;
    std::string_view random_part() const&& = delete;

    bool operator==(const Token&) const noexcept = default;

private:
    std::string text_;
    EntityType label_type_;
};

// 가명화 종류 7개의 라벨. 차단 종류는 token 을 만들지 않으므로 nullopt.
[[nodiscard]] constexpr std::optional<std::string_view> token_label(EntityType type) noexcept {
    if (default_action(type) != Action::Tokenize) {
        return std::nullopt;
    }
    return entity_type_name(type);
}

// 글자 하나라도 다르면 token 이 아니다. 대소문자·공백·괄호를 고치지 않는다(정규화 없음).
[[nodiscard]] std::expected<Token, ProtectionError> parse_token(std::string_view text);

struct TokenOccurrence {
    ByteSpan span;
    Token token;
    bool operator==(const TokenOccurrence&) const noexcept = default;
};

// 텍스트에서 모양이 정확한 token 을 앞에서부터 찾는다. 선형 시간이고, 모양이 틀린 후보는 건너뛴다.
[[nodiscard]] std::vector<TokenOccurrence> scan_tokens(std::string_view text);

}  // namespace prompt_airlock::core
