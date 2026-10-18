#include "prompt_airlock/detect/scan.hpp"

namespace prompt_airlock::detect {
namespace {

// 숫자 사이에 허용하는 구분자. NFKC 뒤라 전각 하이픈·공백류는 이미 ASCII 로 바뀌어 있다.
[[nodiscard]] constexpr bool is_separator(char32_t c) noexcept {
    return c == U'-' || c == U' ' || c == U'.' || (c >= U'‐' && c <= U'―') || c == U'−';
}

[[nodiscard]] constexpr bool is_line_blank(char32_t c) noexcept {
    return c == U' ' || c == U'\t' || c == U'\n' || c == U'\r';
}

// 숫자 사이 구분자는 연속 3개까지(예: "123 - 456").
constexpr std::size_t max_separators = 3;

}  // namespace

std::vector<DigitRun> digit_runs(const DetectionView& view) {
    const auto& u = view.units;
    const std::size_t n = u.size();
    std::vector<DigitRun> runs;
    std::size_t i = 0;
    while (i < n) {
        if (!is_ascii_alnum(u[i].value)) {
            ++i;
            continue;
        }
        // 영문으로 시작하거나 영문 뒤에 붙은 숫자는 식별자 일부라 후보가 아니다. 영숫자 묶음을 통째로 건너뛴다.
        if (!is_ascii_digit(u[i].value)) {
            while (i < n && is_ascii_alnum(u[i].value)) {
                ++i;
            }
            continue;
        }
        DigitRun run;
        std::size_t j = i;
        while (true) {
            DigitGroup group{static_cast<std::uint32_t>(j), 0, {}};
            while (j < n && is_ascii_digit(u[j].value)) {
                group.digits.push_back(static_cast<char>(u[j].value));
                ++j;
            }
            group.last_unit = static_cast<std::uint32_t>(j - 1);
            run.groups.push_back(std::move(group));
            std::size_t k = j;
            while (k < n && k - j < max_separators && is_separator(u[k].value)) {
                ++k;
            }
            if (k == j || k >= n || !is_ascii_digit(u[k].value)) {
                break;
            }
            run.groups.back().separator = u[j].value;
            j = k;
        }
        // 마지막 숫자 바로 뒤가 영문이면 식별자 일부다.
        const bool glued = j < n && is_ascii_alpha(u[j].value);
        if (!glued) {
            runs.push_back(std::move(run));
        }
        i = j;
        while (glued && i < n && is_ascii_alnum(u[i].value)) {
            ++i;
        }
    }
    return runs;
}

std::vector<SentenceSpan> sentences(const DetectionView& view) {
    const auto& u = view.units;
    const auto n = static_cast<std::uint32_t>(u.size());
    std::vector<SentenceSpan> out;
    std::uint32_t start = 0;
    for (std::uint32_t i = 0; i < n; ++i) {
        const char32_t c = u[i].value;
        const bool terminal = c == U'.' || c == U'?' || c == U'!' || c == U'\u3002' || c == U'\u2026';
        const bool next_blank = i + 1 == n || is_line_blank(u[i + 1].value);
        if (c == U'\n' || (terminal && next_blank)) {
            if (i + 1 > start) {
                out.push_back({start, i + 1});
            }
            start = i + 1;
        }
    }
    if (start < n) {
        out.push_back({start, n});
    }
    return out;
}

}  // namespace prompt_airlock::detect
