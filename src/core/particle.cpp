#include "prompt_airlock/core/particle.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace prompt_airlock::core {
namespace {

[[nodiscard]] constexpr bool is_hangul_syllable(char32_t c) noexcept { return c >= 0xAC00 && c <= 0xD7A3; }
[[nodiscard]] constexpr bool has_batchim(char32_t c) noexcept { return is_hangul_syllable(c) && (c - 0xAC00) % 28 != 0; }
[[nodiscard]] constexpr bool has_rieul_batchim(char32_t c) noexcept {
    return is_hangul_syllable(c) && (c - 0xAC00) % 28 == 8;
}

enum class Cond : std::uint8_t { Any, NeedBatchim, NoBatchim, NoBatchimOrRieul, BatchimNotRieul };

struct Particle {
    std::u32string_view text;
    Cond cond;
    std::size_t min_remain;  // 잘라 낸 뒤 남아야 하는 최소 음절 수
};

// 순서가 의미 있다: 긴 조사를 먼저 본다. 목록은 표준 문법의 격조사·보조사 중 이름 뒤에 붙는 것이다.
constexpr std::array<Particle, 47> particles = {{
    {U"으로부터", Cond::BatchimNotRieul, 2}, {U"에서부터", Cond::Any, 2}, {U"에게서", Cond::Any, 2},
    {U"한테서", Cond::Any, 2}, {U"로부터", Cond::NoBatchimOrRieul, 2}, {U"이라도", Cond::NeedBatchim, 2},
    {U"에게", Cond::Any, 2}, {U"께서", Cond::Any, 2}, {U"한테", Cond::Any, 2},
    {U"에서", Cond::Any, 2},   {U"까지", Cond::Any, 2}, {U"부터", Cond::Any, 2}, {U"처럼", Cond::Any, 2},
    {U"보다", Cond::Any, 2},   {U"마저", Cond::Any, 2}, {U"조차", Cond::Any, 2}, {U"밖에", Cond::Any, 2},
    {U"만큼", Cond::Any, 2},   {U"하고", Cond::Any, 2}, {U"라도", Cond::NoBatchim, 2}, {U"이나", Cond::NeedBatchim, 2},
    {U"이며", Cond::NeedBatchim, 2}, {U"이든", Cond::NeedBatchim, 2}, {U"이란", Cond::NeedBatchim, 2},
    {U"이랑", Cond::NeedBatchim, 2}, {U"으로", Cond::BatchimNotRieul, 2},
    {U"은", Cond::NeedBatchim, 2}, {U"는", Cond::NoBatchim, 2}, {U"이", Cond::NeedBatchim, 2},
    {U"가", Cond::NoBatchim, 2},   {U"을", Cond::NeedBatchim, 2}, {U"를", Cond::NoBatchim, 2},
    {U"과", Cond::NeedBatchim, 2}, {U"와", Cond::NoBatchim, 2},
    {U"로", Cond::NoBatchimOrRieul, 2},
    // 랑은 짝이 있지만 이름 끝 글자로 흔해(하랑, 사랑) 세 글자 이상 남을 때만 뗀다.
    {U"랑", Cond::NoBatchim, 3},
    // 짝이 없는 한 음절 조사는 이름 음절과 겹치기 쉬워 더 긴 잔여를 요구한다.
    {U"의", Cond::Any, 3}, {U"도", Cond::Any, 3}, {U"만", Cond::Any, 3}, {U"에", Cond::Any, 3},
    {U"께", Cond::Any, 3}, {U"나", Cond::NoBatchim, 3}, {U"며", Cond::NoBatchim, 3}, {U"든", Cond::NoBatchim, 3},
    {U"란", Cond::NoBatchim, 3},
    // 호칭
    {U"님", Cond::Any, 2}, {U"씨", Cond::Any, 2},
}};

[[nodiscard]] constexpr bool is_ascii_alnum(char32_t c) noexcept {
    return (c >= U'0' && c <= U'9') || (c >= U'A' && c <= U'Z') || (c >= U'a' && c <= U'z');
}

[[nodiscard]] constexpr bool cond_ok(Cond cond, char32_t prev) noexcept {
    // 영문·숫자 뒤(Minsu Kim는, Lee가)는 읽는 소리에 따라 짝 조사 둘 다 쓰여 받침으로 가를 수 없다. 둘 다 받는다.
    if (is_ascii_alnum(prev)) {
        return true;
    }
    switch (cond) {
        case Cond::Any: return true;
        case Cond::NeedBatchim: return has_batchim(prev);
        case Cond::NoBatchim: return is_hangul_syllable(prev) && !has_batchim(prev);
        case Cond::NoBatchimOrRieul: return is_hangul_syllable(prev) && (!has_batchim(prev) || has_rieul_batchim(prev));
        case Cond::BatchimNotRieul: return has_batchim(prev) && !has_rieul_batchim(prev);
    }
    return false;
}

}  // namespace

ByteSpan trim_trailing_particles(std::span<const DecodedCodepoint> units, ByteSpan span) noexcept {
    for (int round = 0; round < 2; ++round) {
        // 구간 안에 완전히 들어가는 unit 은 정렬돼 있으므로 이분 탐색으로 찾는다.
        const auto first = std::lower_bound(units.begin(), units.end(), span.begin(),
                                            [](const DecodedCodepoint& u, Utf8ByteOffset at) { return u.source.begin() < at; });
        auto last = first;
        while (last != units.end() && last->source.end() <= span.end()) {
            ++last;
        }
        const auto inside = std::span<const DecodedCodepoint>(first, last);

        bool changed = false;
        for (const auto& particle : particles) {
            const auto n = particle.text.size();
            if (inside.size() < n + particle.min_remain) {
                continue;
            }
            const auto tail = inside.last(n);
            const bool match = std::equal(tail.begin(), tail.end(), particle.text.begin(),
                                          [](const DecodedCodepoint& u, char32_t c) { return u.value == c; });
            if (!match || !cond_ok(particle.cond, inside[inside.size() - n - 1].value)) {
                continue;
            }
            span = *ByteSpan::make(span.begin(), tail.front().source.begin());
            changed = true;
            break;
        }
        if (!changed) {
            break;
        }
    }
    return span;
}

}  // namespace prompt_airlock::core
