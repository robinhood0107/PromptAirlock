#include "prompt_airlock/detect/view.hpp"

#include <utf8proc.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <memory>
#include <string>

namespace prompt_airlock::detect {
namespace {

namespace pc = core;

constexpr auto nfkc_options =
    static_cast<utf8proc_option_t>(UTF8PROC_STABLE | UTF8PROC_COMPOSE | UTF8PROC_COMPAT);

[[nodiscard]] constexpr bool is_zero_width(char32_t c) noexcept {
    return c == U'​' || c == U'‌' || c == U'‍' || c == U'⁠' || c == U'﻿';
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

std::expected<DetectionView, pc::DetectError> make_view(std::string_view text) {
    auto decoded = pc::decode_utf8(text);
    if (!decoded) {
        return std::unexpected(pc::DetectError::Unavailable);
    }

    // 1. zero-width 를 빼고, 글자마다 호환 분해(NFKD)한다. 분해된 글자는 원래 글자의 원문 구간을 물려받는다.
    std::string stripped;
    stripped.reserve(text.size());
    std::vector<Decomposed> nfkd;
    nfkd.reserve(decoded->size());
    std::array<utf8proc_int32_t, 32> buf{};
    for (const auto& unit : *decoded) {
        if (is_zero_width(unit.value)) {
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
