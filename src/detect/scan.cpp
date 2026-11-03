#include "prompt_airlock/detect/scan.hpp"

namespace prompt_airlock::detect {
namespace {

// 숫자 사이에 허용하는 구분자. NFKC 뒤라 전각 하이픈·공백류는 이미 ASCII 로 바뀌어 있다.
// 줄바꿈·탭도 받는다(#234, 결정 #235): PDF 는 줄 끝에서 번호를 끊고, 표는 번호 앞뒤를 칸으로 나누기도 한다.
[[nodiscard]] constexpr bool is_line_break(char32_t c) noexcept { return c == U'\n' || c == U'\r'; }

[[nodiscard]] constexpr bool is_dash(char32_t c) noexcept {
    return c == U'-' || (c >= U'‐' && c <= U'―') || c == U'−';
}

[[nodiscard]] constexpr bool is_separator(char32_t c) noexcept {
    return is_dash(c) || c == U' ' || c == U'.' || c == U'\t' || is_line_break(c);
}

[[nodiscard]] constexpr bool is_line_blank(char32_t c) noexcept {
    return c == U' ' || c == U'\t' || c == U'\n' || c == U'\r';
}

// 숫자 사이 구분자는 줄바꿈을 빼고 연속 3개까지(예: "123 - 456"), 줄바꿈은 한 번까지(CRLF 는 한 번).
// 줄바꿈을 건너 잇는 것은 줄바꿈 바로 옆에 하이픈이 있을 때("900101-" 줄바꿈 "1234567", 줄바꿈 "-1234567"), 번호마다
// 한 번뿐이다. 줄 나눔 규칙(UAX #14)은 숫자 사이가 아니라 하이픈 뒤에서 끊기 때문이다. 표에서 줄마다 놓인 날짜·항목 번호
// ("25.10.21", "1-1")가 주민번호·카드로 이어져 문서가 차단되던 것을 막는다(받은 문서 측정, #234).
// 놓치는 꼴: 숫자 묶음 가운데서 줄이 끊긴 번호("900101-123" 줄바꿈 "4567"), 하이픈 없는 번호.
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
        bool run_wrapped = false;  // 번호 하나는 줄에서 한 번만 끊긴다(줄마다 놓인 "1-1", "1-2" 를 잇지 않음)
        while (true) {
            DigitGroup group{static_cast<std::uint32_t>(j), 0, {}};
            while (j < n && is_ascii_digit(u[j].value)) {
                group.digits.push_back(static_cast<char>(u[j].value));
                ++j;
            }
            group.last_unit = static_cast<std::uint32_t>(j - 1);
            run.groups.push_back(std::move(group));
            std::size_t k = j;
            std::size_t visible = 0;
            std::size_t newlines = 0;
            char32_t separator = 0;  // 줄바꿈이 아닌 첫 구분자. 줄바꿈만 있으면 빈칸으로 본다(계좌 형식 비교용)
            while (k < n && k - j < max_separators + 2 && is_separator(u[k].value)) {
                const char32_t c = u[k].value;
                if (is_line_break(c)) {
                    newlines += c == U'\n' ? 1 : 0;
                } else {
                    ++visible;
                    separator = separator == 0 ? c : separator;
                }
                if (visible > max_separators || newlines > 1) {
                    break;
                }
                ++k;
            }
            bool dash = false;
            for (std::size_t s = j; s < k; ++s) {
                dash = dash || is_dash(u[s].value);
            }
            if (k == j || k >= n || !is_ascii_digit(u[k].value) || (newlines > 0 && (run_wrapped || !dash))) {
                break;
            }
            run_wrapped = run_wrapped || newlines > 0;
            run.groups.back().separator = separator == 0 ? U' ' : separator;
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
