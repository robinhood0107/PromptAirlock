#include "prompt_airlock/detect/view.hpp"

#include <utf8proc.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace prompt_airlock::detect {
namespace {

namespace pc = core;

constexpr auto nfkc_options =
    static_cast<utf8proc_option_t>(UTF8PROC_STABLE | UTF8PROC_COMPOSE | UTF8PROC_COMPAT);

// 번호·이메일을 끊는 보이지 않는 글자(#234): 서식 문자 Cf(zero-width, soft hyphen, BOM, U+2063 등),
// 탭·줄바꿈 밖의 제어 문자(C0, DEL, C1), 비문자 U+FFFE/FFFF(PDFium 이 대응표 없는 글자에 넣음).
[[nodiscard]] bool is_invisible(char32_t c) noexcept {
    if (c < 0x20) {
        return c != U'\t' && c != U'\n' && c != U'\r';
    }
    if ((c >= 0x7F && c < 0xA0) || c == 0xFFFE || c == 0xFFFF) {
        return true;
    }
    return c >= 0x80 && utf8proc_category(static_cast<utf8proc_int32_t>(c)) == UTF8PROC_CATEGORY_CF;
}

// LaTeX 표기를 지울 글자를 고른다(ViewKind::WithoutLatex). \영문명령, \, \! \; \: \-(쌍째), \{ \$ \_ 같은
// 이스케이프(역슬래시만), { } $, % 에서 줄 끝까지(줄바꿈과 다음 줄 앞 빈칸 포함, LaTeX 가 줄을 잇는 방식).
// ~(LaTeX 의 붙는 빈칸)는 한글 문서에서 기간 표시("2025. 10. 21 ~ 2026. 3. 7")라 그대로 둔다. 날짜가 번호로 붙는다.
// 인자 없는 사용자 정의 명령(\newcommand{\a}{9001}, \def\a{9001})은 정의를 지우고 쓴 자리에 내용을 넣는다(결정 #238).
// 내용은 ASCII 64자까지, 정의는 256개까지, 한 단계만 펼친다(TeX 를 돌리지 않음). 넣은 글자는 쓴 명령의 원문 구간을 가진다.
struct Insert {
    std::u32string body;
    std::size_t last = 0;  // 쓴 명령의 마지막 글자
};

constexpr std::size_t max_macros = 256;
constexpr std::size_t max_macro_body = 64;

[[nodiscard]] bool is_alpha(char32_t c) noexcept { return (c | 0x20U) >= U'a' && (c | 0x20U) <= U'z'; }

[[nodiscard]] std::u32string name_at(std::span<const pc::DecodedCodepoint> d, std::size_t i) {
    std::u32string name;
    while (i < d.size() && is_alpha(d[i].value)) {
        name.push_back(d[i++].value);
    }
    return name;
}

// at 에서 시작하는 정의를 읽는다. 성공하면 (이름, 내용, 정의 끝 다음 위치).
[[nodiscard]] std::optional<std::tuple<std::u32string, std::u32string, std::size_t>> read_definition(
    std::span<const pc::DecodedCodepoint> d, std::size_t at) {
    const auto n = d.size();
    const auto skip_space = [&](std::size_t i) {
        while (i < n && (d[i].value == U' ' || d[i].value == U'\t')) {
            ++i;
        }
        return i;
    };
    const auto keyword = name_at(d, at + 1);
    const bool def = keyword == U"def";
    if (!def && keyword != U"newcommand" && keyword != U"renewcommand" && keyword != U"providecommand") {
        return std::nullopt;
    }
    std::size_t i = skip_space(at + 1 + keyword.size());
    if (!def && i < n && d[i].value == U'*') {
        i = skip_space(i + 1);
    }
    const bool braced = !def && i < n && d[i].value == U'{';
    i = skip_space(i + (braced ? 1 : 0));
    if (i >= n || d[i].value != U'\\') {
        return std::nullopt;
    }
    auto name = name_at(d, i + 1);
    if (name.empty()) {
        return std::nullopt;
    }
    i += 1 + name.size();
    if (braced) {
        i = skip_space(i);
        if (i >= n || d[i].value != U'}') {
            return std::nullopt;
        }
        ++i;
    }
    i = skip_space(i);
    if (i >= n || d[i].value != U'{') {
        return std::nullopt;  // 인자가 있는 정의([1], #1)는 펼치지 않는다
    }
    std::u32string body;
    int depth = 0;
    for (; i < n; ++i) {
        const char32_t c = d[i].value;
        if (c == U'{') {
            ++depth;
        } else if (c == U'}') {
            if (--depth == 0) {
                return std::tuple{std::move(name), std::move(body), i + 1};
            }
        } else if (c == U'\\' || c == U'#' || c >= 0x80 || body.size() >= max_macro_body) {
            return std::nullopt;  // 다른 명령·인자·비 ASCII 를 품은 내용은 펼치지 않는다
        } else if (c != U'$') {
            body.push_back(c);
        }
    }
    return std::nullopt;
}

void mark_latex(std::span<const pc::DecodedCodepoint> d, std::vector<bool>& drop, std::vector<Insert>& insert) {
    const auto alpha = is_alpha;
    const auto n = d.size();
    std::vector<std::pair<std::u32string, std::u32string>> macros;
    for (std::size_t i = 0; i < n; ++i) {
        const char32_t c = d[i].value;
        if (c == U'\\') {
            if (macros.size() < max_macros) {
                if (auto definition = read_definition(d, i)) {
                    auto& [name, body, end] = *definition;
                    std::erase_if(macros, [&](const auto& m) { return m.first == name; });
                    macros.emplace_back(std::move(name), std::move(body));
                    for (std::size_t k = i; k < end; ++k) {
                        drop[k] = true;
                    }
                    i = end - 1;
                    continue;
                }
            }
            drop[i] = true;
            if (i + 1 >= n) {
                break;
            }
            const char32_t next = d[i + 1].value;
            if (alpha(next)) {
                const auto name = name_at(d, i + 1);
                const auto used = std::ranges::find(macros, name, &std::pair<std::u32string, std::u32string>::first);
                const auto first = i;
                while (i + 1 < n && alpha(d[i + 1].value)) {
                    drop[++i] = true;
                }
                if (used != macros.end()) {
                    insert[first] = {used->second, i};
                }
            } else if (std::u32string_view(U",!;:-").find(next) != std::u32string_view::npos) {
                drop[++i] = true;
            } else {
                ++i;  // 이스케이프한 글자와 "\ "(빈칸)는 남긴다
            }
        } else if (c == U'{' || c == U'}' || c == U'$' || c == U'[' || c == U']') {
            drop[i] = true;  // [ ] 는 Typst 내용 묶음(900101#[-]1234567)
        } else if (c == U'#' && i + 1 < n && (is_alpha(d[i + 1].value) || d[i + 1].value == U'[')) {
            // Typst 함수·기호 부르기(#sym.dash, #text). 이름과 점으로 이은 하위 이름까지 지운다.
            drop[i] = true;
            while (i + 1 < n && (is_alpha(d[i + 1].value) || d[i + 1].value == U'.')) {
                drop[++i] = true;
            }
        } else if (c == U'%') {
            while (i < n && d[i].value != U'\n') {
                drop[i++] = true;
            }
            if (i < n) {
                drop[i] = true;
            }
            while (i + 1 < n && (d[i + 1].value == U' ' || d[i + 1].value == U'\t')) {
                drop[++i] = true;
            }
        }
    }
}

// 한글 조합형 자모. 앞 글자와 합쳐질 수 있는 모음(V)·받침(T)은 starter 지만 새 구간을 시작하지 않는다.
[[nodiscard]] constexpr bool is_leading_jamo(char32_t c) noexcept { return c >= 0x1100 && c <= 0x1112; }
[[nodiscard]] constexpr bool is_vowel_jamo(char32_t c) noexcept { return c >= 0x1161 && c <= 0x1175; }
[[nodiscard]] constexpr bool is_trailing_jamo(char32_t c) noexcept { return c >= 0x11A8 && c <= 0x11C2; }

struct FreeDeleter {
    void operator()(utf8proc_uint8_t* p) const noexcept { std::free(p); }
};

// utf8proc_map 으로 NFKC 를 만들어 out 에 코드포인트로 붙인다. 실패하면 false.
[[nodiscard]] bool nfkc(std::string_view utf8, std::u32string& out) {
    utf8proc_uint8_t* raw = nullptr;
    const auto n = utf8proc_map(reinterpret_cast<const utf8proc_uint8_t*>(utf8.data()),
                                static_cast<utf8proc_ssize_t>(utf8.size()), &raw, nfkc_options);
    const std::unique_ptr<utf8proc_uint8_t, FreeDeleter> owned(raw);
    if (n < 0) {
        return false;
    }
    for (utf8proc_ssize_t pos = 0; pos < n;) {
        utf8proc_int32_t cp = 0;
        const auto k = utf8proc_iterate(owned.get() + pos, n - pos, &cp);
        if (k <= 0) {
            return false;
        }
        out.push_back(static_cast<char32_t>(cp));
        pos += k;
    }
    return true;
}

void append_utf8(std::string& out, char32_t c) {
    std::array<utf8proc_uint8_t, 4> buf{};
    const auto k = utf8proc_encode_char(static_cast<utf8proc_int32_t>(c), buf.data());
    out.append(reinterpret_cast<const char*>(buf.data()), static_cast<std::size_t>(k));
}

struct Decomposed {
    char32_t value;
    pc::ByteSpan source;
};

}  // namespace

std::expected<DetectionView, pc::DetectError> make_view(std::string_view text, ViewKind kind) {
    auto decoded = pc::decode_utf8(text);
    if (!decoded) {
        return std::unexpected(pc::DetectError::Unavailable);
    }
    std::vector<bool> drop(decoded->size(), false);
    std::vector<Insert> insert(kind == ViewKind::WithoutLatex ? decoded->size() : 0);
    if (kind == ViewKind::WithoutLatex) {
        mark_latex(*decoded, drop, insert);
    }

    // 1. 보이지 않는 글자(와 LaTeX 표기)를 빼고, 글자마다 호환 분해(NFKD)한다. 분해된 글자는 원래 글자의 원문 구간을 물려받는다.
    std::string stripped;
    stripped.reserve(text.size());
    std::vector<Decomposed> nfkd;
    nfkd.reserve(decoded->size());
    std::array<utf8proc_int32_t, 32> buf{};
    for (std::size_t k = 0; k < decoded->size(); ++k) {
        const auto& unit = (*decoded)[k];
        if (!insert.empty() && !insert[k].body.empty()) {
            // 펼친 명령 내용(ASCII). 글자마다 쓴 명령 전체의 원문 구간을 준다.
            const auto span = pc::ByteSpan::hull(unit.source, (*decoded)[insert[k].last].source);
            for (const char32_t c : insert[k].body) {
                stripped.push_back(static_cast<char>(c));
                nfkd.push_back({c, span});
            }
        }
        if (drop[k] || is_invisible(unit.value)) {
            continue;
        }
        stripped.append(text.substr(unit.source.begin().value(), unit.source.size()));
        if (unit.value < 0x80) {
            nfkd.push_back({unit.value, unit.source});
            continue;
        }
        int boundclass = UTF8PROC_BOUNDCLASS_START;
        const auto n = utf8proc_decompose_char(static_cast<utf8proc_int32_t>(unit.value), buf.data(),
                                               static_cast<utf8proc_ssize_t>(buf.size()),
                                               static_cast<utf8proc_option_t>(UTF8PROC_DECOMPOSE | UTF8PROC_COMPAT),
                                               &boundclass);
        if (n < 0 || n > static_cast<utf8proc_ssize_t>(buf.size())) {
            return std::unexpected(pc::DetectError::Unavailable);
        }
        for (utf8proc_ssize_t i = 0; i < n; ++i) {
            nfkd.push_back({static_cast<char32_t>(buf[static_cast<std::size_t>(i)]), unit.source});
        }
    }

    // 2. 결합이 넘지 않는 구간으로 나눠 구간마다 NFKC 를 만든다. 구간의 결과 글자는 구간 원문 전체를 가리킨다.
    DetectionView view;
    view.units.reserve(nfkd.size());
    std::string chunk_text;
    std::u32string chunk_out;
    for (std::size_t begin = 0; begin < nfkd.size();) {
        std::size_t end = begin + 1;
        while (end < nfkd.size()) {
            const char32_t c = nfkd[end].value;
            const char32_t prev = nfkd[end - 1].value;
            const bool joins = utf8proc_get_property(static_cast<utf8proc_int32_t>(c))->combining_class != 0 ||
                               (is_vowel_jamo(c) && is_leading_jamo(prev)) ||
                               (is_trailing_jamo(c) && is_vowel_jamo(prev));
            if (!joins) {
                break;
            }
            ++end;
        }
        auto span = nfkd[begin].source;
        for (std::size_t i = begin + 1; i < end; ++i) {
            span = pc::ByteSpan::hull(span, nfkd[i].source);
        }
        if (end == begin + 1 && nfkd[begin].value < 0x80) {
            view.units.push_back({nfkd[begin].value, span});
        } else {
            chunk_text.clear();
            chunk_out.clear();
            for (std::size_t i = begin; i < end; ++i) {
                append_utf8(chunk_text, nfkd[i].value);
            }
            if (!nfkc(chunk_text, chunk_out)) {
                return std::unexpected(pc::DetectError::Unavailable);
            }
            for (const char32_t c : chunk_out) {
                view.units.push_back({c, span});
            }
        }
        begin = end;
    }

    // 3. 구간별 결과가 전체 NFKC 와 같아야 한다. 다르면 구간 가정이 깨진 입력이므로 거절한다.
    std::u32string whole;
    if (!nfkc(stripped, whole) || whole.size() != view.units.size() ||
        !std::equal(whole.begin(), whole.end(), view.units.begin(),
                    [](char32_t c, const pc::DecodedCodepoint& u) { return c == u.value; })) {
        return std::unexpected(pc::DetectError::Unavailable);
    }
    return view;
}

pc::ByteSpan source_span(const DetectionView& view, std::uint32_t first, std::uint32_t last) noexcept {
    return pc::ByteSpan::hull(view.units[first].source, view.units[last].source);
}

}  // namespace prompt_airlock::detect
