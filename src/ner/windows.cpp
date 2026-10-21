#include "prompt_airlock/ner/windows.hpp"

#include <algorithm>

namespace prompt_airlock::ner {

std::optional<std::vector<TokenWindow>> split_windows(std::uint32_t tokens, std::span<const std::uint32_t> cut_after) {
    static_assert(window_overlap_tokens < window_body_tokens);  // 되돌아가도 창마다 앞으로 나아간다
    std::vector<TokenWindow> out;
    std::uint32_t start = 0;
    while (start < tokens) {
        if (out.size() == max_ner_windows) {
            return std::nullopt;
        }
        const std::uint32_t limit = std::min(tokens, start + window_body_tokens);
        if (limit == tokens) {
            out.push_back({start, tokens});
            break;
        }
        // [start, limit) 안에서 자를 수 있는 가장 늦은 자리. cut 뒤에서 자르면 창 끝은 cut + 1 이다.
        const auto after = std::ranges::upper_bound(cut_after, limit - 1);
        if (after != cut_after.begin() && *std::prev(after) >= start) {
            const std::uint32_t end = *std::prev(after) + 1;
            out.push_back({start, end});
            start = end;
        } else {
            out.push_back({start, limit});
            start = limit - window_overlap_tokens;
        }
    }
    return out;
}

}  // namespace prompt_airlock::ner
