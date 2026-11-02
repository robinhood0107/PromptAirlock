// 글자 형식: 인코딩 판별(UTF-8, UTF-16, CP949)과 htm 글자 뽑기.
#include <algorithm>
#include <array>
#include <cstdint>

#include "data/cp949_table.hpp"
#include "detail.hpp"

namespace prompt_airlock::extract::detail {
namespace {

[[nodiscard]] constexpr unsigned char byte_at(std::string_view s, std::size_t i) noexcept {
    return static_cast<unsigned char>(s[i]);
}

[[nodiscard]] std::expected<std::string, ExtractError> utf16_to_utf8(std::string_view bytes, bool big_endian) {
    if (bytes.size() % 2 != 0) {
        return std::unexpected(ExtractError::Damaged);
    }
    std::string out;
    out.reserve(bytes.size());
    for (std::size_t i = 0; i < bytes.size(); i += 2) {
        const auto unit = [&](std::size_t at) {
            return big_endian ? static_cast<char16_t>(byte_at(bytes, at) << 8 | byte_at(bytes, at + 1))
                              : static_cast<char16_t>(byte_at(bytes, at + 1) << 8 | byte_at(bytes, at));
        };
        char32_t cp = unit(i);
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (i + 3 >= bytes.size()) {
                return std::unexpected(ExtractError::Damaged);
            }
            const char32_t low = unit(i + 2);
            if (low < 0xDC00 || low > 0xDFFF) {
                return std::unexpected(ExtractError::Damaged);
            }
            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
            i += 2;
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            return std::unexpected(ExtractError::Damaged);
        }
        if (cp == 0) {
            return std::unexpected(ExtractError::UnknownFormat);
        }
        append_utf8(out, cp);
    }
    return out;
}

// 이름 있는 문자 참조 가운데 문서에 흔한 것만. 나머지는 그대로 둔다(글자가 사라지지 않게).
constexpr std::array<std::pair<std::string_view, char32_t>, 8> named_refs = {{
    {"amp", U'&'}, {"lt", U'<'}, {"gt", U'>'}, {"quot", U'"'}, {"apos", U'\''}, {"nbsp", U' '}, {"middot", U'·'},
    {"hellip", U'…'},
}};

[[nodiscard]] bool iequals_prefix(std::string_view s, std::size_t at, std::string_view word) noexcept {
    if (s.size() - at < word.size()) {
        return false;
    }
    for (std::size_t k = 0; k < word.size(); ++k) {
        const auto c = static_cast<char>(s[at + k] >= 'A' && s[at + k] <= 'Z' ? s[at + k] + 32 : s[at + k]);
        if (c != word[k]) {
            return false;
        }
    }
    return true;
}

}  // namespace

void append_utf8(std::string& out, char32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | cp >> 6));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | cp >> 12));
        out.push_back(static_cast<char>(0x80 | (cp >> 6 & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | cp >> 18));
        out.push_back(static_cast<char>(0x80 | (cp >> 12 & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp >> 6 & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

bool valid_utf8(std::string_view s) noexcept {
    for (std::size_t i = 0; i < s.size();) {
        const auto c = byte_at(s, i);
        std::size_t n = 0;
        char32_t cp = 0;
        if (c < 0x80) {
            ++i;
            continue;
        }
        if (c >= 0xC2 && c <= 0xDF) {
            n = 1;
            cp = c & 0x1F;
        } else if (c >= 0xE0 && c <= 0xEF) {
            n = 2;
            cp = c & 0x0F;
        } else if (c >= 0xF0 && c <= 0xF4) {
            n = 3;
            cp = c & 0x07;
        } else {
            return false;
        }
        if (i + n >= s.size()) {
            return false;
        }
        for (std::size_t k = 1; k <= n; ++k) {
            const auto t = byte_at(s, i + k);
            if ((t & 0xC0) != 0x80) {
                return false;
            }
            cp = cp << 6 | (t & 0x3F);
        }
        // 길게 쓴 꼴(overlong), 대리 쌍 자리, U+10FFFF 초과를 막는다.
        if ((n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return false;
        }
        i += n + 1;
    }
    return true;
}

std::expected<std::string, ExtractError> cp949_to_utf8(std::string_view bytes) {
    std::string out;
    out.reserve(bytes.size() * 3 / 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const unsigned lead = byte_at(bytes, i);
        if (lead < 0x80) {
            out.push_back(static_cast<char>(lead));
            continue;
        }
        if (lead < data::cp949_lead_first || lead > data::cp949_lead_last || i + 1 >= bytes.size()) {
            return std::unexpected(ExtractError::UnknownFormat);
        }
        const unsigned trail = byte_at(bytes, ++i);
        if (trail < data::cp949_trail_first || trail > data::cp949_trail_last) {
            return std::unexpected(ExtractError::UnknownFormat);
        }
        const auto cp = data::cp949_table[(lead - data::cp949_lead_first) * data::cp949_trail_count +
                                          (trail - data::cp949_trail_first)];
        if (cp == 0) {
            return std::unexpected(ExtractError::UnknownFormat);
        }
        append_utf8(out, cp);
    }
    return out;
}

std::expected<std::string, ExtractError> decode_text(std::span<const std::byte> raw) {
    const std::string_view bytes(reinterpret_cast<const char*>(raw.data()), raw.size());
    if (bytes.starts_with("\xEF\xBB\xBF")) {
        const auto rest = bytes.substr(3);
        if (!valid_utf8(rest) || rest.find('\0') != std::string_view::npos) {
            return std::unexpected(ExtractError::Damaged);
        }
        return std::string(rest);
    }
    if (bytes.starts_with("\xFF\xFE")) {
        return utf16_to_utf8(bytes.substr(2), false);
    }
    if (bytes.starts_with("\xFE\xFF")) {
        return utf16_to_utf8(bytes.substr(2), true);
    }
    if (bytes.find('\0') != std::string_view::npos) {
        return std::unexpected(ExtractError::UnknownFormat);  // 글자 파일이 아니다
    }
    if (valid_utf8(bytes)) {
        return std::string(bytes);
    }
    return cp949_to_utf8(bytes);
}

std::vector<std::string> html_lines(std::string_view html) {
    std::string text;
    for (std::size_t i = 0; i < html.size();) {
        if (html[i] == '<') {
            if (html.substr(i, 4) == "<!--") {
                const auto end = html.find("-->", i + 4);
                i = end == std::string_view::npos ? html.size() : end + 3;
                continue;
            }
            const bool script = iequals_prefix(html, i, "<script");
            const bool style = iequals_prefix(html, i, "<style");
            const auto close = html.find('>', i);
            if (close == std::string_view::npos) {
                break;
            }
            const auto tag = html.substr(i, close - i + 1);
            if (script || style) {
                // 닫는 태그까지 통째로 건너뛴다(대소문자 무시).
                const std::string_view end_tag = script ? "</script" : "</style";
                std::size_t j = close + 1;
                while (j < html.size() && !iequals_prefix(html, j, end_tag)) {
                    ++j;
                }
                const auto end_close = html.find('>', j);
                i = end_close == std::string_view::npos ? html.size() : end_close + 1;
                continue;
            }
            // 줄을 끊는 태그는 줄바꿈으로, 칸을 나누는 태그는 탭으로.
            for (const std::string_view breaker : {"<br", "</p", "<p", "</div", "</tr", "</li", "</h", "<h"}) {
                if (iequals_prefix(tag, 0, breaker)) {
                    text.push_back('\n');
                    break;
                }
            }
            if (iequals_prefix(tag, 0, "</td") || iequals_prefix(tag, 0, "</th")) {
                text.push_back('\t');
            }
            i = close + 1;
            continue;
        }
        if (html[i] == '&') {
            const auto semi = html.find(';', i);
            if (semi != std::string_view::npos && semi - i <= 10) {
                const auto ref = html.substr(i + 1, semi - i - 1);
                char32_t cp = 0;
                if (ref.starts_with("#x") || ref.starts_with("#X")) {
                    for (const char c : ref.substr(2)) {
                        const int d = c >= '0' && c <= '9' ? c - '0' : (c | 0x20) >= 'a' && (c | 0x20) <= 'f' ? (c | 0x20) - 'a' + 10 : -1;
                        cp = d < 0 || cp > 0x10FFFF ? 0x110000 : cp * 16 + static_cast<char32_t>(d);
                    }
                } else if (ref.starts_with("#")) {
                    for (const char c : ref.substr(1)) {
                        cp = c < '0' || c > '9' || cp > 0x10FFFF ? 0x110000 : cp * 10 + static_cast<char32_t>(c - '0');
                    }
                } else {
                    for (const auto& [name, value] : named_refs) {
                        cp = ref == name ? value : cp;
                    }
                }
                if (cp != 0 && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF)) {
                    append_utf8(text, cp);
                    i = semi + 1;
                    continue;
                }
            }
        }
        text.push_back(html[i] == '\r' ? '\n' : html[i]);
        ++i;
    }
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start <= text.size()) {
        auto end = text.find('\n', start);
        if (end == std::string::npos) {
            end = text.size();
        }
        auto line = std::string_view(text).substr(start, end - start);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
            line.remove_prefix(1);
        }
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) {
            line.remove_suffix(1);
        }
        if (!line.empty()) {
            lines.emplace_back(line);
        }
        start = end + 1;
    }
    return lines;
}

std::expected<void, ExtractError> Context::add(std::string where, std::string text) {
    if (std::ranges::all_of(text, [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; })) {
        return {};
    }
    output += text.size();
    if (output > limits.output_bytes) {
        return std::unexpected(ExtractError::TooLarge);
    }
    doc.blocks.push_back({prefix + where, std::move(text)});
    return {};
}

}  // namespace prompt_airlock::extract::detail
