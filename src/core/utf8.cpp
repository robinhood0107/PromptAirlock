#include "prompt_airlock/core/utf8.hpp"

#include <cstddef>

namespace prompt_airlock::core {
namespace {

struct Decoded {
    char32_t value;
    std::size_t length;
};

[[nodiscard]] constexpr bool is_continuation(unsigned char byte) noexcept { return (byte & 0xC0U) == 0x80U; }

// text[at] 에서 시작하는 코드포인트 하나를 읽는다. 규칙은 Phase 2 spike 의 decode_utf8 과 같다.
[[nodiscard]] std::expected<Decoded, InputError> decode_one(std::string_view text, std::size_t at) noexcept {
    const auto lead = static_cast<unsigned char>(text[at]);
    if (lead < 0x80U) {
        return Decoded{lead, 1};
    }
    char32_t value = 0;
    std::size_t length = 0;
    char32_t minimum = 0;
    if ((lead & 0xE0U) == 0xC0U) {
        value = lead & 0x1FU;
        length = 2;
        minimum = 0x80;
    } else if ((lead & 0xF0U) == 0xE0U) {
        value = lead & 0x0FU;
        length = 3;
        minimum = 0x800;
    } else if ((lead & 0xF8U) == 0xF0U) {
        value = lead & 0x07U;
        length = 4;
        minimum = 0x10000;
    } else {
        return std::unexpected(InputError::InvalidUtf8);
    }
    if (length > text.size() - at) {
        return std::unexpected(InputError::InvalidUtf8);
    }
    for (std::size_t k = 1; k < length; ++k) {
        const auto byte = static_cast<unsigned char>(text[at + k]);
        if (!is_continuation(byte)) {
            return std::unexpected(InputError::InvalidUtf8);
        }
        value = (value << 6U) | (byte & 0x3FU);
    }
    if (value < minimum || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF)) {
        return std::unexpected(InputError::InvalidUtf8);
    }
    return Decoded{value, length};
}

}  // namespace

std::expected<void, InputError> validate_utf8(std::string_view text) noexcept {
    std::size_t at = 0;
    while (at < text.size()) {
        const auto one = decode_one(text, at);
        if (!one) {
            return std::unexpected(one.error());
        }
        at += one->length;
    }
    return {};
}

std::expected<std::vector<DecodedCodepoint>, InputError> decode_utf8(std::string_view text) {
    std::vector<DecodedCodepoint> out;
    out.reserve(text.size());
    std::size_t at = 0;
    while (at < text.size()) {
        const auto one = decode_one(text, at);
        if (!one) {
            return std::unexpected(one.error());
        }
        // length 가 1 이상이라 구간은 항상 비어 있지 않다.
        const auto span = ByteSpan::make(Utf8ByteOffset{at}, Utf8ByteOffset{at + one->length});
        out.push_back(DecodedCodepoint{one->value, *span});
        at += one->length;
    }
    return out;
}

bool is_codepoint_boundary(std::string_view text, Utf8ByteOffset at) noexcept {
    if (at.value() > text.size()) {
        return false;
    }
    if (at.value() == text.size()) {
        return true;
    }
    return !is_continuation(static_cast<unsigned char>(text[at.value()]));
}

std::expected<void, InputError> check_span(std::string_view text, ByteSpan span) noexcept {
    if (span.end().value() > text.size()) {
        return std::unexpected(InputError::OffsetOutOfRange);
    }
    if (!is_codepoint_boundary(text, span.begin()) || !is_codepoint_boundary(text, span.end())) {
        return std::unexpected(InputError::NotCodepointBoundary);
    }
    return {};
}

std::expected<CodepointOffset, InputError> to_codepoint_offset(std::string_view text, Utf8ByteOffset at) noexcept {
    if (at.value() > text.size()) {
        return std::unexpected(InputError::OffsetOutOfRange);
    }
    if (!is_codepoint_boundary(text, at)) {
        return std::unexpected(InputError::NotCodepointBoundary);
    }
    std::size_t count = 0;
    for (std::size_t i = 0; i < at.value(); ++i) {
        if (!is_continuation(static_cast<unsigned char>(text[i]))) {
            ++count;
        }
    }
    return CodepointOffset{count};
}

std::expected<Utf8ByteOffset, InputError> to_byte_offset(std::string_view text, CodepointOffset at) noexcept {
    std::size_t count = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (!is_continuation(static_cast<unsigned char>(text[i]))) {
            if (count == at.value()) {
                return Utf8ByteOffset{i};
            }
            ++count;
        }
    }
    if (count == at.value()) {
        return Utf8ByteOffset{text.size()};
    }
    return std::unexpected(InputError::OffsetOutOfRange);
}

}  // namespace prompt_airlock::core
