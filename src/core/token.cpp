#include "prompt_airlock/core/token.hpp"

#include <algorithm>
#include <utility>

#include "state_access.hpp"

namespace prompt_airlock::core {
namespace {

// 가장 긴 라벨(24자) + '_' + R(10자). 이보다 먼 닫는 괄호는 볼 필요가 없다.
constexpr std::size_t max_inner_length = 24 + 1 + token_random_length;

[[nodiscard]] std::optional<EntityType> label_type(std::string_view label) noexcept {
    for (const auto type : all_entity_types()) {
        if (const auto known = token_label(type); known && *known == label) {
            return type;
        }
    }
    return std::nullopt;
}

}  // namespace

Token::Token(detail::StateKey<Token>, std::string text, EntityType label_type) noexcept
    : text_(std::move(text)), label_type_(label_type) {}

std::string_view Token::random_part() const& noexcept {
    return std::string_view(text_).substr(text_.size() - token_close.size() - token_random_length, token_random_length);
}

std::expected<Token, ProtectionError> parse_token(std::string_view text) {
    if (!text.starts_with(token_open) || !text.ends_with(token_close)) {
        return std::unexpected(ProtectionError::MalformedToken);
    }
    const auto inner = text.substr(token_open.size(), text.size() - token_open.size() - token_close.size());
    const auto underscore = inner.rfind('_');
    if (underscore == std::string_view::npos) {
        return std::unexpected(ProtectionError::MalformedToken);
    }
    const auto random = inner.substr(underscore + 1);
    const bool random_ok = random.size() == token_random_length &&
                           std::all_of(random.begin(), random.end(),
                                       [](char c) { return token_alphabet.find(c) != std::string_view::npos; });
    const auto type = label_type(inner.substr(0, underscore));
    if (!random_ok || !type) {
        return std::unexpected(ProtectionError::MalformedToken);
    }
    return Token(detail::StateAccess::key<Token>(), std::string(text), *type);
}

std::vector<TokenOccurrence> scan_tokens(std::string_view text) {
    std::vector<TokenOccurrence> out;
    std::size_t at = text.find(token_open);
    while (at != std::string_view::npos) {
        const auto inner_begin = at + token_open.size();
        const auto window = text.substr(inner_begin, max_inner_length + token_close.size());
        const auto close = window.find(token_close);
        if (close != std::string_view::npos) {
            const auto end = inner_begin + close + token_close.size();
            if (auto token = parse_token(text.substr(at, end - at))) {
                const auto span = ByteSpan::make(Utf8ByteOffset{at}, Utf8ByteOffset{end});
                out.push_back(TokenOccurrence{*span, std::move(*token)});
                at = text.find(token_open, end);
                continue;
            }
        }
        // 모양이 틀린 후보는 여는 괄호만 넘기고 다시 찾는다(⟦⟦PERSON_…⟧ 같은 겹친 경우).
        at = text.find(token_open, inner_begin);
    }
    return out;
}

}  // namespace prompt_airlock::core
