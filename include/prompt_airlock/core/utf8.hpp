#pragma once

#include <expected>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/offset.hpp"

namespace prompt_airlock::core {

// 코드포인트 하나와 그것이 온 원문 byte 구간.
struct DecodedCodepoint {
    char32_t value;
    ByteSpan source;
};

// 엄격 검증: overlong, surrogate, U+10FFFF 초과, 잘린 문자, 떠도는 continuation byte 를 거절한다.
[[nodiscard]] std::expected<void, InputError> validate_utf8(std::string_view text) noexcept;
[[nodiscard]] std::expected<std::vector<DecodedCodepoint>, InputError> decode_utf8(std::string_view text);

// 아래 함수들은 text 가 이미 검증된 UTF-8 이라고 가정한다.
[[nodiscard]] bool is_codepoint_boundary(std::string_view text, Utf8ByteOffset at) noexcept;
[[nodiscard]] std::expected<void, InputError> check_span(std::string_view text, ByteSpan span) noexcept;
[[nodiscard]] std::expected<CodepointOffset, InputError> to_codepoint_offset(std::string_view text,
                                                                           Utf8ByteOffset at) noexcept;
[[nodiscard]] std::expected<Utf8ByteOffset, InputError> to_byte_offset(std::string_view text,
                                                                     CodepointOffset at) noexcept;

}  // namespace prompt_airlock::core
