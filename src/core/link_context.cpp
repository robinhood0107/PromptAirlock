#include "prompt_airlock/core/link_context.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace prompt_airlock::core {
namespace {

using Mask = std::vector<LinkContext>;

[[nodiscard]] constexpr char lower(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }
[[nodiscard]] constexpr bool is_alpha(char c) noexcept { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
[[nodiscard]] constexpr bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }
[[nodiscard]] constexpr bool is_alnum(char c) noexcept { return is_alpha(c) || is_digit(c); }
[[nodiscard]] constexpr bool is_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}
[[nodiscard]] constexpr bool is_scheme_char(char c) noexcept { return is_alnum(c) || c == '+' || c == '.' || c == '-'; }

// 대소문자를 무시하고 text[at..] 가 word 로 시작하는가.
[[nodiscard]] bool starts_with_ci(std::string_view text, std::size_t at, std::string_view word) noexcept {
    if (at > text.size() || text.size() - at < word.size()) {
        return false;
    }
    for (std::size_t i = 0; i < word.size(); ++i) {
        if (lower(text[at + i]) != word[i]) {
            return false;
        }
    }
    return true;
}

void mark(Mask& mask, std::size_t begin, std::size_t end, LinkContext context) {
    for (auto i = begin; i < end && i < mask.size(); ++i) {
        if (mask[i] == LinkContext::None) {
            mask[i] = context;
        }
    }
}

[[nodiscard]] std::size_t line_end(std::string_view text, std::size_t from) noexcept {
    const auto at = text.find('\n', from);
    return at == std::string_view::npos ? text.size() : at;
}

// "//" 없이 쓰는 scheme. 렌더러가 링크로 만들거나 값을 담아 보낼 수 있는 것들이다.
constexpr std::array<std::string_view, 18> fixed_schemes = {
    "mailto", "tel", "sms", "data", "javascript", "vbscript", "file", "blob", "urn",
    "news", "magnet", "geo", "sip", "sips", "xmpp", "cid", "mid", "im"};

// L4: HTML 태그. 따옴표 안의 '>' 는 넘긴다. 닫히지 않으면 텍스트 끝까지.
// &lt; 같은 문자 참조로 쓴 태그도 같이 본다(두 번 해석하는 앱이 있다).
void mark_tags_and_angles(std::string_view text, Mask& mask) {
    std::size_t i = 0;
    while (i < text.size()) {
        std::size_t open_len = 0;
        bool entity = false;
        if (text[i] == '<') {
            open_len = 1;
        } else if (text[i] == '&') {
            for (const auto form : {std::string_view("&lt;"), std::string_view("&#60;"), std::string_view("&#x3c;")}) {
                if (starts_with_ci(text, i, form)) {
                    open_len = form.size();
                    entity = true;
                    break;
                }
            }
        }
        if (open_len == 0 || i + open_len >= text.size()) {
            ++i;
            continue;
        }
        const char next = text[i + open_len];
        if (is_alpha(next) || next == '/' || next == '!') {
            std::size_t j = i + open_len;
            std::size_t end = text.size();
            while (j < text.size()) {
                const char c = text[j];
                if (c == '"' || c == '\'') {
                    const auto close = text.find(c, j + 1);
                    j = close == std::string_view::npos ? text.size() : close + 1;
                    continue;
                }
                if (c == '>') {
                    end = j + 1;
                    break;
                }
                if (entity && starts_with_ci(text, j, "&gt;")) {
                    end = j + 4;
                    break;
                }
                ++j;
            }
            mark(mask, i, end, LinkContext::HtmlTag);
            i = end;
        } else if (!entity && !is_space(next)) {
            // L3: <주소> 자동 링크나 <token> 처럼 공백 없이 시작하는 꺾쇠. 줄 끝을 넘지 않는다.
            // 앞으로만 훑고 끝난 자리부터 이어 가므로 '<' 가 많아도 선형이다.
            auto end = i + 1;
            while (end < text.size() && text[end] != '>' && text[end] != '\n') {
                ++end;
            }
            if (end < text.size() && text[end] == '>') {
                ++end;
            }
            mark(mask, i, end, LinkContext::AngleBracket);
            i = end;
        } else {
            i += open_len;
        }
    }
}

// L1: ](주소). 괄호 깊이를 세고 \) 는 넘긴다. 닫히지 않으면 텍스트 끝까지.
void mark_markdown_destinations(std::string_view text, Mask& mask) {
    auto at = text.find("](");
    while (at != std::string_view::npos) {
        const auto start = at + 2;
        std::size_t end = text.size();
        int depth = 0;
        for (auto j = start; j < text.size(); ++j) {
            if (text[j] == '\\') {
                ++j;
            } else if (text[j] == '(') {
                ++depth;
            } else if (text[j] == ')') {
                if (depth == 0) {
                    end = j;
                    break;
                }
                --depth;
            }
        }
        mark(mask, start, end, LinkContext::MarkdownDestination);
        at = end >= text.size() ? std::string_view::npos : text.find("](", end);
    }
}

// L2: 줄 앞 공백 0~3개 + [이름]: 뒤 줄 끝까지.
void mark_markdown_references(std::string_view text, Mask& mask) {
    std::size_t line = 0;
    while (line < text.size()) {
        const auto end = line_end(text, line);
        auto i = line;
        while (i < end && i - line < 3 && text[i] == ' ') {
            ++i;
        }
        if (i < end && text[i] == '[') {
            const auto close = text.substr(0, end).find(']', i + 1);
            if (close != std::string_view::npos && close + 1 < end && text[close + 1] == ':') {
                mark(mask, close + 2, end, LinkContext::MarkdownReference);
            }
        }
        line = end + 1;
    }
}

// L9: url( · image-set( 는 닫는 괄호까지(없으면 끝까지), @import 는 줄 끝까지. 앞이 영숫자면 다른 단어다.
void mark_css(std::string_view text, Mask& mask) {
    std::size_t i = 0;
    while (i < text.size()) {
        if (i > 0 && (is_alnum(text[i - 1]) || text[i - 1] == '-')) {
            ++i;
            continue;
        }
        std::size_t end = i;
        for (const auto opener : {std::string_view("url("), std::string_view("image-set(")}) {
            if (starts_with_ci(text, i, opener)) {
                const auto close = text.find(')', i + opener.size());
                end = close == std::string_view::npos ? text.size() : close + 1;
                break;
            }
        }
        if (end == i && starts_with_ci(text, i, "@import")) {
            end = line_end(text, i);
        }
        if (end > i) {
            mark(mask, i, end, LinkContext::CssUrl);
            i = end;  // 칠한 구간은 다시 훑지 않는다(닫는 괄호가 없으면 끝까지 칠하고 끝난다)
        } else {
            ++i;
        }
    }
}

[[nodiscard]] LinkContext run_context(std::string_view run) {
    if (run.find("://") != std::string_view::npos) {
        return LinkContext::SchemeUrl;
    }
    // 고정 scheme: ':' 앞의 가장 긴 scheme 글자 묶음이 목록에 있으면.
    for (std::size_t colon = run.find(':'); colon != std::string_view::npos; colon = run.find(':', colon + 1)) {
        auto start = colon;
        while (start > 0 && is_scheme_char(run[start - 1])) {
            --start;
        }
        if (start < colon && is_alpha(run[start])) {
            std::string scheme;
            for (auto k = start; k < colon; ++k) {
                scheme.push_back(lower(run[k]));
            }
            if (std::find(fixed_schemes.begin(), fixed_schemes.end(), scheme) != fixed_schemes.end()) {
                return LinkContext::SchemeUrl;
            }
        }
    }
    // www. 앞의 여는 기호는 건너뛴다.
    std::size_t lead = 0;
    while (lead < run.size() && std::string_view("([*_\"'<").find(run[lead]) != std::string_view::npos) {
        ++lead;
    }
    if (starts_with_ci(run, lead, "www.")) {
        return LinkContext::WwwUrl;
    }
    // 이름.tld 뒤에 / ? # :숫자 가 오면 주소로 본다(tld 는 영문 2자 이상).
    for (std::size_t dot = run.find('.'); dot != std::string_view::npos; dot = run.find('.', dot + 1)) {
        if (dot == 0 || !(is_alnum(run[dot - 1]) || run[dot - 1] == '-')) {
            continue;
        }
        auto end = dot + 1;
        while (end < run.size() && is_alpha(run[end])) {
            ++end;
        }
        if (end - dot - 1 < 2 || end >= run.size()) {
            continue;
        }
        const char after = run[end];
        if (after == '/' || after == '?' || after == '#' ||
            (after == ':' && end + 1 < run.size() && is_digit(run[end + 1]))) {
            return LinkContext::HostPath;
        }
    }
    return LinkContext::None;
}

// L5~L8: ASCII 공백으로만 끊은 run 하나가 주소처럼 보이면 run 전체를 칠한다.
void mark_runs(std::string_view text, Mask& mask) {
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && is_space(text[i])) {
            ++i;
        }
        auto end = i;
        while (end < text.size() && !is_space(text[end])) {
            ++end;
        }
        if (end > i) {
            if (const auto context = run_context(text.substr(i, end - i)); context != LinkContext::None) {
                mark(mask, i, end, context);
            }
        }
        i = end;
    }
}

}  // namespace

std::vector<LinkContext> classify_link_contexts(std::string_view response, std::span<const TokenOccurrence> tokens) {
    Mask mask(response.size(), LinkContext::None);
    mark_tags_and_angles(response, mask);
    mark_markdown_destinations(response, mask);
    mark_markdown_references(response, mask);
    mark_css(response, mask);
    mark_runs(response, mask);

    std::vector<LinkContext> out;
    out.reserve(tokens.size());
    for (const auto& occurrence : tokens) {
        auto context = LinkContext::None;
        for (auto b = occurrence.span.begin().value(); b < occurrence.span.end().value() && b < mask.size(); ++b) {
            if (mask[b] != LinkContext::None) {
                context = mask[b];
                break;
            }
        }
        out.push_back(context);
    }
    return out;
}

std::expected<void, Rejection> check_link_contexts(std::string_view response, std::span<const TokenOccurrence> tokens) {
    const auto contexts = classify_link_contexts(response, tokens);
    std::vector<AuditFinding> findings;
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        if (contexts[i] != LinkContext::None) {
            findings.emplace_back(ResponseLocation{tokens[i].span});
        }
    }
    if (!findings.empty()) {
        return std::unexpected(Rejection::with_findings(ReasonCode::ResponseTokenInLink, {}, std::move(findings)));
    }
    return {};
}

}  // namespace prompt_airlock::core
