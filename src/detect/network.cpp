// 이메일(RFC 5321 길이 한도)과 IP 주소(IPv4 RFC 791 점 표기, IPv6 RFC 4291 2.2절 텍스트 표기).
#include <string_view>

#include "prompt_airlock/detect/scan.hpp"
#include "rules.hpp"

namespace prompt_airlock::detect::rules {
namespace {

using core::DetectorKind;
using core::EntityType;

constexpr std::size_t max_local_part = 64;
constexpr std::size_t max_domain = 255;
constexpr std::size_t max_ipv6_text = 45;

[[nodiscard]] constexpr bool is_local_char(char32_t c) noexcept {
    return is_ascii_alnum(c) || std::u32string_view(U"!#$%&'*+/=?^_`{|}~.-").find(c) != std::u32string_view::npos;
}
[[nodiscard]] constexpr bool is_domain_char(char32_t c) noexcept { return is_ascii_alnum(c) || c == U'.' || c == U'-'; }
[[nodiscard]] constexpr bool is_hex(char32_t c) noexcept {
    return is_ascii_digit(c) || (ascii_lower(c) >= U'a' && ascii_lower(c) <= U'f');
}

// 점으로 나뉜 label 이 2개 이상, 비지 않고 '-' 로 시작·끝나지 않으며, 마지막 label 은 영문 2자 이상.
[[nodiscard]] bool is_domain(std::u32string_view d) noexcept {
    std::size_t labels = 0;
    std::u32string_view last;
    while (true) {
        const auto dot = d.find(U'.');
        const auto label = d.substr(0, dot);
        if (label.empty() || label.front() == U'-' || label.back() == U'-') {
            return false;
        }
        ++labels;
        last = label;
        if (dot == std::u32string_view::npos) {
            break;
        }
        d.remove_prefix(dot + 1);
    }
    if (labels < 2 || last.size() < 2) {
        return false;
    }
    for (const char32_t c : last) {
        if (!is_ascii_alpha(c)) {
            return false;
        }
    }
    return true;
}

// '@' 마다 왼쪽 local part, 오른쪽 domain 을 넓힌다. 양쪽 모두 '@' 에서 멈추므로 글자마다 최대 두 번 본다.
void find_emails(std::u32string_view text, std::vector<Hit>& out) {
    for (std::size_t at = text.find(U'@'); at != std::u32string_view::npos; at = text.find(U'@', at + 1)) {
        std::size_t begin = at;
        while (begin > 0 && at - begin < max_local_part && is_local_char(text[begin - 1])) {
            --begin;
        }
        while (begin < at && text[begin] == U'.') {
            ++begin;
        }
        std::size_t end = at + 1;
        while (end < text.size() && end - at - 1 < max_domain && is_domain_char(text[end])) {
            ++end;
        }
        while (end > at + 1 && (text[end - 1] == U'.' || text[end - 1] == U'-')) {
            --end;  // 문장 끝 마침표
        }
        if (begin == at || text[at - 1] == U'.' || !is_domain(text.substr(at + 1, end - at - 1))) {
            continue;
        }
        out.push_back({static_cast<std::uint32_t>(begin), static_cast<std::uint32_t>(end - 1), EntityType::Email,
                       DetectorKind::Pattern});
    }
}

// IPv4 네 마디. 마디는 0~255, 0 이 아닌 수는 0 으로 시작하지 않는다. 성공하면 끝 위치(다음 글자).
[[nodiscard]] std::size_t parse_ipv4(std::u32string_view t, std::size_t i) noexcept {
    for (int part = 0; part < 4; ++part) {
        if (part > 0) {
            if (i >= t.size() || t[i] != U'.') {
                return 0;
            }
            ++i;
        }
        const std::size_t start = i;
        int value = 0;
        while (i < t.size() && is_ascii_digit(t[i]) && i - start < 3) {
            value = value * 10 + static_cast<int>(t[i] - U'0');
            ++i;
        }
        if (i == start || value > 255 || (i - start > 1 && t[start] == U'0')) {
            return 0;
        }
    }
    return i;
}

void find_ipv4(std::u32string_view text, std::vector<Hit>& out) {
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (!is_ascii_digit(text[i]) || (i > 0 && (is_ascii_alnum(text[i - 1]) || text[i - 1] == U'.'))) {
            continue;
        }
        const std::size_t end = parse_ipv4(text, i);
        // 뒤에 숫자·영문이 붙거나 ".숫자" 가 이어지면 더 긴 점 표기(버전 문자열 등)다.
        if (end == 0 || (end < text.size() && is_ascii_alnum(text[end])) ||
            (end + 1 < text.size() && text[end] == U'.' && is_ascii_digit(text[end + 1]))) {
            continue;
        }
        out.push_back({static_cast<std::uint32_t>(i), static_cast<std::uint32_t>(end - 1), EntityType::IpAddress,
                       DetectorKind::Pattern});
        i = end - 1;
    }
}

// RFC 4291 2.2절: 16진수 1~4자리 마디 8개, "::" 는 한 번만(0 마디 생략), 끝에 IPv4 점 표기 허용.
[[nodiscard]] bool is_ipv6(std::u32string_view t) noexcept {
    const auto gap = t.find(U"::");
    if (gap != std::u32string_view::npos && t.find(U"::", gap + 1) != std::u32string_view::npos) {
        return false;
    }
    std::size_t groups = 0;
    std::size_t i = 0;
    if (gap == 0) {
        i = 2;
    }
    while (i < t.size()) {
        const std::size_t start = i;
        while (i < t.size() && is_hex(t[i]) && i - start < 4) {
            ++i;
        }
        if (i < t.size() && t[i] == U'.') {
            // 끝 IPv4 는 마디 2개 몫이다.
            if (parse_ipv4(t, start) != t.size()) {
                return false;
            }
            groups += 2;
            break;
        }
        if (i == start) {
            return false;
        }
        ++groups;
        if (i == t.size()) {
            break;
        }
        if (t[i] != U':') {
            return false;
        }
        ++i;
        if (i < t.size() && t[i] == U':') {
            ++i;  // "::"
        } else if (i == t.size()) {
            return false;  // ':' 로 끝남
        }
    }
    return gap == std::u32string_view::npos ? groups == 8 : groups >= 1 && groups <= 7;
}

void find_ipv6(std::u32string_view text, std::vector<Hit>& out) {
    const auto is_part = [](char32_t c) { return is_hex(c) || c == U':' || c == U'.'; };
    std::size_t i = 0;
    while (i < text.size()) {
        if (!is_part(text[i]) || (i > 0 && is_ascii_alnum(text[i - 1]))) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < text.size() && is_part(text[j])) {
            ++j;
        }
        std::size_t end = j;
        while (end > i && text[end - 1] == U'.') {
            --end;  // 문장 끝 마침표
        }
        const auto token = text.substr(i, end - i);
        const bool glued = j < text.size() && is_ascii_alnum(text[j]);
        if (!glued && token.size() <= max_ipv6_text && token.find(U':') != std::u32string_view::npos &&
            is_ipv6(token)) {
            out.push_back({static_cast<std::uint32_t>(i), static_cast<std::uint32_t>(end - 1), EntityType::IpAddress,
                           DetectorKind::Pattern});
        }
        i = j;
    }
}

}  // namespace

void find_network(std::u32string_view text, std::vector<Hit>& out) {
    find_emails(text, out);
    find_ipv4(text, out);
    find_ipv6(text, out);
}

}  // namespace prompt_airlock::detect::rules
