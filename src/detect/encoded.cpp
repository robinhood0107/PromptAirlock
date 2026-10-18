#include "prompt_airlock/detect/encoded.hpp"

#include <array>
#include <cstdint>

#include "prompt_airlock/core/utf8.hpp"

namespace prompt_airlock::detect {
namespace {

using core::EncodingKind;

constexpr std::size_t min_blob = 16;

[[nodiscard]] constexpr int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}
[[nodiscard]] constexpr bool is_hex(char c) noexcept { return hex_value(c) >= 0; }
[[nodiscard]] constexpr bool is_alnum(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
[[nodiscard]] constexpr bool is_blob_char(char c) noexcept {
    return is_alnum(c) || c == '+' || c == '/' || c == '_' || c == '-';
}
[[nodiscard]] constexpr bool is_printable(char c) noexcept { return c > ' ' && c < 0x7F; }

[[nodiscard]] bool hex_at(std::string_view s, std::size_t i, std::size_t n) noexcept {
    if (i + n > s.size()) {
        return false;
    }
    for (std::size_t k = 0; k < n; ++k) {
        if (!is_hex(s[i + k])) {
            return false;
        }
    }
    return true;
}

// 덩어리 안의 %XX, &#..;, \uXXXX 개수.
struct EscapeCounts {
    std::size_t percent = 0;
    std::size_t html = 0;
    std::size_t unicode = 0;
};
[[nodiscard]] EscapeCounts count_escapes(std::string_view t) noexcept {
    EscapeCounts c;
    for (std::size_t i = 0; i < t.size(); ++i) {
        if (t[i] == '%' && hex_at(t, i + 1, 2)) {
            ++c.percent;
        } else if (t[i] == '\\' && i + 1 < t.size() && t[i + 1] == 'u' && hex_at(t, i + 2, 4)) {
            ++c.unicode;
        } else if (t[i] == '&' && i + 2 < t.size() && t[i + 1] == '#') {
            const bool hex = t[i + 2] == 'x' || t[i + 2] == 'X';
            std::size_t j = i + (hex ? 3 : 2);
            const std::size_t start = j;
            while (j < t.size() && (hex ? is_hex(t[j]) : (t[j] >= '0' && t[j] <= '9'))) {
                ++j;
            }
            if (j > start && j < t.size() && t[j] == ';') {
                ++c.html;
            }
        }
    }
    return c;
}

void append_utf8(std::string& out, char32_t c) {
    if (c < 0x80) {
        out.push_back(static_cast<char>(c));
    } else if (c < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (c >> 6)));
        out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else if (c < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (c >> 12)));
        out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (c >> 18)));
        out.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
    }
}

[[nodiscard]] constexpr bool is_scalar(std::uint32_t c) noexcept { return c <= 0x10FFFF && (c < 0xD800 || c > 0xDFFF); }

[[nodiscard]] std::optional<std::string> decode_base64(std::string_view s, bool url) {
    while (!s.empty() && s.back() == '=') {
        s.remove_suffix(1);
    }
    if (s.size() % 4 == 1) {
        return std::nullopt;
    }
    std::string out;
    out.reserve(s.size() * 3 / 4);
    std::uint32_t acc = 0;
    int bits = 0;
    for (const char c : s) {
        int v = -1;
        if (c >= 'A' && c <= 'Z') {
            v = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            v = c - 'a' + 26;
        } else if (c >= '0' && c <= '9') {
            v = c - '0' + 52;
        } else if (c == (url ? '-' : '+')) {
            v = 62;
        } else if (c == (url ? '_' : '/')) {
            v = 63;
        }
        if (v < 0) {
            return std::nullopt;
        }
        acc = (acc << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

[[nodiscard]] std::optional<std::string> decode_escapes(std::string_view s, EncodingKind kind) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        if (kind == EncodingKind::Percent && s[i] == '%' && hex_at(s, i + 1, 2)) {
            out.push_back(static_cast<char>(hex_value(s[i + 1]) * 16 + hex_value(s[i + 2])));
            i += 3;
        } else if (kind == EncodingKind::UnicodeEscape && s[i] == '\\' && i + 1 < s.size() && s[i + 1] == 'u' &&
                   hex_at(s, i + 2, 4)) {
            std::uint32_t unit = 0;
            for (std::size_t k = 0; k < 4; ++k) {
                unit = unit * 16 + static_cast<std::uint32_t>(hex_value(s[i + 2 + k]));
            }
            i += 6;
            if (unit >= 0xD800 && unit <= 0xDBFF) {
                // 대리 쌍: 바로 뒤에 낮은 대리가 와야 한다.
                if (!(i + 1 < s.size() && s[i] == '\\' && s[i + 1] == 'u' && hex_at(s, i + 2, 4))) {
                    return std::nullopt;
                }
                std::uint32_t low = 0;
                for (std::size_t k = 0; k < 4; ++k) {
                    low = low * 16 + static_cast<std::uint32_t>(hex_value(s[i + 2 + k]));
                }
                if (low < 0xDC00 || low > 0xDFFF) {
                    return std::nullopt;
                }
                unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                i += 6;
            }
            if (!is_scalar(unit)) {
                return std::nullopt;
            }
            append_utf8(out, static_cast<char32_t>(unit));
        } else if (kind == EncodingKind::HtmlNumericRef && s[i] == '&' && i + 2 < s.size() && s[i + 1] == '#') {
            const bool hex = s[i + 2] == 'x' || s[i + 2] == 'X';
            std::size_t j = i + (hex ? 3 : 2);
            std::uint32_t value = 0;
            const std::size_t start = j;
            while (j < s.size() && j - start < 8 && (hex ? is_hex(s[j]) : (s[j] >= '0' && s[j] <= '9'))) {
                value = value * (hex ? 16U : 10U) + static_cast<std::uint32_t>(hex_value(s[j]));
                ++j;
            }
            if (j == start || j >= s.size() || s[j] != ';' || !is_scalar(value)) {
                return std::nullopt;
            }
            append_utf8(out, static_cast<char32_t>(value));
            i = j + 1;
        } else {
            out.push_back(s[i]);
            ++i;
        }
    }
    return out;
}

}  // namespace

std::vector<EncodedCandidate> encoded_candidates(std::string_view text) {
    std::vector<EncodedCandidate> out;
    const auto add = [&](std::size_t begin, std::size_t end, EncodingKind kind) {
        out.push_back({*core::ByteSpan::make(core::Utf8ByteOffset{begin}, core::Utf8ByteOffset{end}), kind});
    };
    std::size_t i = 0;
    while (i < text.size()) {
        if (!is_printable(text[i])) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < text.size() && is_printable(text[j])) {
            ++j;
        }
        const auto token = text.substr(i, j - i);
        const auto counts = count_escapes(token);
        if (counts.percent >= 3) {
            add(i, j, EncodingKind::Percent);
        } else if (counts.html >= 2) {
            add(i, j, EncodingKind::HtmlNumericRef);
        } else if (counts.unicode >= 2) {
            add(i, j, EncodingKind::UnicodeEscape);
        } else {
            // 덩어리 안의 base64·hex 글자 묶음(끝 '=' 2개까지).
            std::size_t k = 0;
            while (k < token.size()) {
                if (!is_blob_char(token[k]) || (k > 0 && is_blob_char(token[k - 1]))) {
                    ++k;
                    continue;
                }
                std::size_t e = k;
                bool all_hex = true, url = false, std_chars = false;
                while (e < token.size() && is_blob_char(token[e])) {
                    all_hex = all_hex && is_hex(token[e]);
                    url = url || token[e] == '-' || token[e] == '_';
                    std_chars = std_chars || token[e] == '+' || token[e] == '/';
                    ++e;
                }
                std::size_t pad = e;
                while (pad < token.size() && pad - e < 2 && token[pad] == '=') {
                    ++pad;
                }
                if (pad - k >= min_blob) {
                    const auto kind = all_hex && pad == e && (e - k) % 2 == 0 ? EncodingKind::Hex
                                      : url && !std_chars                   ? EncodingKind::Base64Url
                                                                            : EncodingKind::Base64;
                    add(i + k, i + pad, kind);
                }
                k = pad;
            }
        }
        i = j;
    }
    return out;
}

std::optional<std::string> decode(std::string_view blob, EncodingKind kind) {
    switch (kind) {
        case EncodingKind::Base64:
            return decode_base64(blob, false);
        case EncodingKind::Base64Url:
            return decode_base64(blob, true);
        case EncodingKind::Hex: {
            if (blob.size() % 2 != 0) {
                return std::nullopt;
            }
            std::string out;
            out.reserve(blob.size() / 2);
            for (std::size_t i = 0; i < blob.size(); i += 2) {
                if (!is_hex(blob[i]) || !is_hex(blob[i + 1])) {
                    return std::nullopt;
                }
                out.push_back(static_cast<char>(hex_value(blob[i]) * 16 + hex_value(blob[i + 1])));
            }
            return out;
        }
        case EncodingKind::Percent:
        case EncodingKind::HtmlNumericRef:
        case EncodingKind::UnicodeEscape:
            return decode_escapes(blob, kind);
    }
    return std::nullopt;
}

bool is_text(std::string_view bytes) noexcept {
    if (bytes.empty() || !core::validate_utf8(bytes)) {
        return false;
    }
    for (const char c : bytes) {
        const auto u = static_cast<unsigned char>(c);
        if ((u < 0x20 && c != '\t' && c != '\n' && c != '\r') || u == 0x7F) {
            return false;
        }
    }
    return true;
}

}  // namespace prompt_airlock::detect
