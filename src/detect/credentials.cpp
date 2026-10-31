// 인증 정보(ADR 0016): 표지어 뒤 값, URL 안의 사용자 이름·비밀번호, HTTP Basic 값, 계정 문맥 + 무작위 문자열.
// 접속 문자열의 Password=·Pwd= 값은 표지어 규칙이 '=' 구분으로 잡는다.
#include <algorithm>
#include <string>
#include <string_view>

#include "data/credential_markers.hpp"
#include "rules.hpp"

namespace prompt_airlock::detect::rules {
namespace {

using core::DetectorKind;
using core::EntityType;

void push(std::vector<Hit>& out, std::size_t first, std::size_t last) {
    out.push_back({static_cast<std::uint32_t>(first), static_cast<std::uint32_t>(last), EntityType::Credential,
                   DetectorKind::Secret});
}

[[nodiscard]] constexpr bool is_blank(char32_t c) noexcept { return c == U' ' || c == U'\t'; }
[[nodiscard]] constexpr bool is_ascii_symbol(char32_t c) noexcept {
    return c > U' ' && c < 0x7F && !is_ascii_alnum(c);
}
// 값이 끝나는 글자. 따옴표·괄호·구분 기호는 값에 넣지 않는다.
[[nodiscard]] constexpr bool ends_value(char32_t c) noexcept {
    return c == U' ' || c == U'\t' || c == U'\n' || c == U'\r' ||
           std::u32string_view(U";,\"'`)]}>&").find(c) != std::u32string_view::npos;
}

[[nodiscard]] std::size_t skip_blank(std::u32string_view text, std::size_t i) noexcept {
    while (i < text.size() && is_blank(text[i])) {
        ++i;
    }
    return i;
}

struct Value {
    std::size_t first;
    std::size_t end;  // 끝 다음 위치
};

// 표지어 끝(marker_end) 뒤의 값. ':' '=' 는 강한 구분, 은/는/이/가/is 는 약한 구분이다.
// 강한 구분 뒤 값은 ASCII 글자가 하나라도 있으면 받고, 약한 구분 뒤 값은 숫자나 기호가 있어야 받는다
// ("비밀번호는 주기적으로 바꾸세요", "password is required" 는 값이 아니다).
[[nodiscard]] std::optional<Value> value_after(std::u32string_view text, std::size_t marker_end) {
    std::size_t i = skip_blank(text, marker_end);
    for (const auto s : data::marker_suffixes) {
        if (text.substr(i, s.size()) == s) {
            marker_end = i + s.size();
            i = skip_blank(text, marker_end);
            break;
        }
    }
    bool strong = false;
    if (i < text.size() && (text[i] == U':' || text[i] == U'=')) {
        strong = true;
        ++i;
    } else {
        bool particle = false;
        for (const auto p : data::marker_particles) {
            const bool ascii = is_ascii_alpha(p[0]);
            if (text.substr(i, p.size()) == p && (!ascii || (i == marker_end + 1 && i + p.size() < text.size() &&
                                                              is_blank(text[i + p.size()])))) {
                i += p.size();
                particle = true;
                break;
            }
        }
        if (!particle) {
            return std::nullopt;
        }
    }
    i = skip_blank(text, i);
    std::size_t end = i;
    while (end < text.size() && end - i < data::credential_value_max && !ends_value(text[end])) {
        ++end;
    }
    while (end > i && (text[end - 1] == U'.' || text[end - 1] == U',')) {
        --end;  // 문장 끝 마침표
    }
    if (end == i) {
        return std::nullopt;
    }
    const auto value = text.substr(i, end - i);
    const bool has_ascii = std::ranges::any_of(value, [](char32_t c) { return is_ascii_alnum(c) || is_ascii_symbol(c); });
    const bool has_digit_or_symbol =
        std::ranges::any_of(value, [](char32_t c) { return is_ascii_digit(c) || is_ascii_symbol(c); });
    if (strong ? !has_ascii : !has_digit_or_symbol) {
        return std::nullopt;
    }
    return Value{i, end};
}

// URL 안의 사용자 이름과 비밀번호: scheme://user:pass@host. user:pass 를 차단한다.
void find_userinfo(std::u32string_view text, std::vector<Hit>& out) {
    for (std::size_t s = text.find(U"://"); s != std::u32string_view::npos; s = text.find(U"://", s + 3)) {
        const std::size_t begin = s + 3;
        std::size_t i = begin;
        std::size_t colon = std::u32string_view::npos;
        while (i < text.size() && text[i] != U'@' && text[i] != U'/' && text[i] != U'?' && text[i] != U'#' &&
               !is_blank(text[i]) && text[i] != U'\n') {
            if (text[i] == U':' && colon == std::u32string_view::npos) {
                colon = i;
            }
            ++i;
        }
        if (i < text.size() && text[i] == U'@' && colon != std::u32string_view::npos && colon + 1 < i) {
            push(out, begin, i - 1);
        }
    }
}

// "Authorization: Basic <base64>". "basic" 은 흔한 단어라 앞 30자 안에 authorization 이 있을 때만 본다.
void find_basic(std::u32string_view text, std::vector<Hit>& out) {
    constexpr std::u32string_view word = U"basic";
    constexpr std::u32string_view header = U"authorization";
    constexpr std::size_t header_window = 30;
    std::u32string lower(text);
    std::ranges::transform(lower, lower.begin(), ascii_lower);
    for (std::size_t b = lower.find(word); b != std::u32string::npos; b = lower.find(word, b + 1)) {
        const std::size_t from = b > header_window ? b - header_window : 0;
        if (std::u32string_view(lower).substr(from, b - from).find(header) == std::u32string_view::npos) {
            continue;
        }
        const std::size_t v = skip_blank(text, b + word.size());
        if (v == b + word.size()) {
            continue;
        }
        std::size_t e = v;
        while (e < text.size() && (is_ascii_alnum(text[e]) || text[e] == U'+' || text[e] == U'/' || text[e] == U'=')) {
            ++e;
        }
        if (e - v >= data::basic_min_length) {
            push(out, v, e - 1);
        }
    }
}

// 무작위 문자열: 8자 이상, 대문자·소문자·숫자·기호(구분 기호 제외) 가운데 3종류 이상, 영문 부분이 흔한 단어가 아님.
[[nodiscard]] bool looks_random(std::u32string_view token) {
    if (token.size() < data::random_min_length || token.find(U"://") != std::u32string_view::npos ||
        token.find(U'@') != std::u32string_view::npos) {
        return false;
    }
    bool upper = false, lower = false, digit = false, symbol = false;
    std::string letters;
    for (const char32_t c : token) {
        upper = upper || (c >= U'A' && c <= U'Z');
        lower = lower || (c >= U'a' && c <= U'z');
        digit = digit || is_ascii_digit(c);
        // '-', '_', '.' 는 업무 번호의 구분 기호라 기호 종류로 세지 않는다(REQ-2026-001234, 2026-10-18 결정).
        symbol = symbol || (is_ascii_symbol(c) && c != U'-' && c != U'_' && c != U'.');
        if (is_ascii_alpha(c)) {
            letters.push_back(static_cast<char>(ascii_lower(c)));
        }
    }
    const int classes = int{upper} + int{lower} + int{digit} + int{symbol};
    return static_cast<std::size_t>(classes) >= data::random_min_classes &&
           std::ranges::find(data::common_words, letters) == data::common_words.end();
}

void find_random_near_account(std::u32string_view text, const Nearby& account, std::vector<Hit>& out) {
    std::size_t i = 0;
    while (i < text.size()) {
        if (!(text[i] > U' ' && text[i] < 0x7F)) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < text.size() && text[j] > U' ' && text[j] < 0x7F) {
            ++j;
        }
        // 토큰 앞뒤의 따옴표·괄호·문장 부호는 값이 아니다.
        std::size_t b = i;
        std::size_t e = j;
        while (b < e && std::u32string_view(U"\"'`([{<:=").find(text[b]) != std::u32string_view::npos) {
            ++b;
        }
        while (e > b && std::u32string_view(U"\"'`)]}>.,;").find(text[e - 1]) != std::u32string_view::npos) {
            --e;
        }
        if (e > b && e - b <= data::credential_value_max && looks_random(text.substr(b, e - b)) &&
            account.around(b, e - 1, data::credential_window)) {
            push(out, b, e - 1);
        }
        i = j;
    }
}

}  // namespace

void find_credentials(std::u32string_view text, const TermMatcher& secret_markers, const TermMatcher& user_markers,
                      const TermMatcher& account_markers, const DetectionView& view, std::vector<Hit>& out) {
    // 1. 비밀 표지어 뒤 값.
    std::vector<std::size_t> secret_starts;
    for (const auto& hit : secret_markers.find(view)) {
        if (const auto v = value_after(text, hit.last_unit + 1)) {
            push(out, v->first, v->end - 1);
            secret_starts.push_back(v->first);
        }
    }
    // 2. 비밀 값이 뒤 40자 안에 있는 계정 이름 값(ID/PW 짝).
    std::ranges::sort(secret_starts);
    for (const auto& hit : user_markers.find(view)) {
        const auto v = value_after(text, hit.last_unit + 1);
        if (!v) {
            continue;
        }
        const auto next = std::ranges::lower_bound(secret_starts, v->end);
        if (next != secret_starts.end() && *next <= v->end + data::credential_window) {
            push(out, v->first, v->end - 1);
        }
    }
    find_userinfo(text, out);
    find_basic(text, out);
    find_random_near_account(text, Nearby(account_markers.find(view)), out);
}

}  // namespace prompt_airlock::detect::rules
