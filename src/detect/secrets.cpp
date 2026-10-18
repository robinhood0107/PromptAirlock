// 비밀 키 탐지: 접두가 있는 키, JWT, Bearer 뒤 값, PEM 개인 키(data/secret_formats.hpp).
#include <algorithm>
#include <string>
#include <string_view>

#include "data/secret_formats.hpp"
#include "prompt_airlock/detect/scan.hpp"
#include "rules.hpp"

namespace prompt_airlock::detect::rules {
namespace {

using core::DetectorKind;
using core::EntityType;

[[nodiscard]] constexpr bool is_key_char(char32_t c) noexcept { return is_ascii_alnum(c) || c == U'_' || c == U'-'; }
[[nodiscard]] constexpr bool is_jwt_char(char32_t c) noexcept { return is_key_char(c) || c == U'.'; }
[[nodiscard]] constexpr bool is_token68_char(char32_t c) noexcept {
    return is_key_char(c) || std::u32string_view(U"._~+/=").find(c) != std::u32string_view::npos;
}

// ASCII 접두 비교. 키 글자는 ASCII 라 char32_t 와 그대로 비교한다.
[[nodiscard]] bool starts_with(std::u32string_view text, std::string_view prefix, bool fold) noexcept {
    if (text.size() < prefix.size()) {
        return false;
    }
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        const char32_t a = fold ? ascii_lower(text[i]) : text[i];
        if (a != static_cast<char32_t>(static_cast<unsigned char>(prefix[i]))) {
            return false;
        }
    }
    return true;
}

constexpr std::size_t max_pem_header = 80;

void push(std::vector<Hit>& out, std::size_t first, std::size_t end) {
    out.push_back({static_cast<std::uint32_t>(first), static_cast<std::uint32_t>(end - 1), EntityType::ApiKey,
                   DetectorKind::Secret});
}

// 키 글자 묶음마다 접두 표와 JWT 모양을 본다.
void find_tokens(std::u32string_view text, std::vector<Hit>& out) {
    std::size_t i = 0;
    while (i < text.size()) {
        if (!is_jwt_char(text[i])) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < text.size() && is_jwt_char(text[j])) {
            ++j;
        }
        const auto token = text.substr(i, j - i);
        if (starts_with(token, data::jwt_head, false)) {
            std::size_t parts = 0;
            std::size_t start = 0;
            bool long_enough = true;
            for (std::size_t k = 0; k <= token.size() && parts < 3; ++k) {
                if (k == token.size() || token[k] == U'.') {
                    long_enough = long_enough && k - start >= data::jwt_min_part;
                    ++parts;
                    start = k + 1;
                }
            }
            if (parts == 3 && long_enough) {
                push(out, i, j);
            }
        }
        // 접두 키는 '.' 를 포함하지 않는다. 묶음 안의 '.' 앞까지를 키 후보로 본다.
        for (std::size_t s = i; s < j;) {
            std::size_t e = s;
            while (e < j && is_key_char(text[e])) {
                ++e;
            }
            const auto key = text.substr(s, e - s);
            for (const auto& p : data::key_prefixes) {
                if (key.size() >= p.min_length && starts_with(key, p.prefix, false)) {
                    push(out, s, e);
                    break;
                }
            }
            s = e + 1;
        }
        i = j;
    }
}

// "Bearer <값>": 단어 경계의 bearer(대소문자 무시) 뒤 공백, 그 뒤 token68 글자 16자 이상.
void find_bearer(std::u32string_view text, std::vector<Hit>& out) {
    const auto n = data::bearer_word.size();
    for (std::size_t i = 0; i + n < text.size(); ++i) {
        if ((i > 0 && is_ascii_alnum(text[i - 1])) || !starts_with(text.substr(i), data::bearer_word, true)) {
            continue;
        }
        std::size_t v = i + n;
        if (text[v] != U' ' && text[v] != U'\t') {
            continue;
        }
        while (v < text.size() && (text[v] == U' ' || text[v] == U'\t')) {
            ++v;
        }
        std::size_t e = v;
        while (e < text.size() && is_token68_char(text[e])) {
            ++e;
        }
        if (e - v >= data::bearer_min_length) {
            push(out, v, e);
        }
        i = e > i ? e - 1 : i;
    }
}

// PEM 개인 키: BEGIN 줄 꼬리가 "PRIVATE KEY-----" 이면 대응 END 줄 끝까지, END 가 없으면 끝까지.
void find_private_keys(std::u32string_view text, std::vector<Hit>& out) {
    const std::u32string begin(data::pem_begin.begin(), data::pem_begin.end());
    const std::u32string end_mark(data::pem_end.begin(), data::pem_end.end());
    const std::u32string tail(data::pem_private_tail.begin(), data::pem_private_tail.end());
    for (std::size_t b = text.find(begin); b != std::u32string_view::npos; b = text.find(begin, b + 1)) {
        // 머리 줄 꼬리는 BEGIN 뒤 가까이에서만 찾는다(한 줄에 BEGIN 이 많아도 선형).
        const auto line_end = std::min({text.find(U'\n', b), text.size(), b + max_pem_header});
        const auto header = text.substr(b, line_end - b);
        const auto at = header.find(tail);
        if (at == std::u32string_view::npos) {
            continue;
        }
        std::size_t stop = text.size();
        if (const auto e = text.find(end_mark, b + at + tail.size()); e != std::u32string_view::npos) {
            const auto close = text.find(tail, e);
            stop = close == std::u32string_view::npos ? text.size() : close + tail.size();
        }
        out.push_back({static_cast<std::uint32_t>(b), static_cast<std::uint32_t>(stop - 1), EntityType::PrivateKey,
                       DetectorKind::Secret});
        b = stop - 1;
    }
}

}  // namespace

void find_secrets(std::u32string_view text, std::vector<Hit>& out) {
    find_tokens(text, out);
    find_bearer(text, out);
    find_private_keys(text, out);
}

}  // namespace prompt_airlock::detect::rules
