// 단어 목록 일치기(Aho-Corasick). 입력을 한 번 지나가며 O(n + 일치 수) 이다.
// ASCII 대소문자를 구분하지 않고, 단어 안의 공백은 건너뛴다("가상 기관"도 "가상기관"과 일치).
// 단어가 ASCII 영숫자로 시작(끝)하면 바로 앞(뒤) 글자가 ASCII 영숫자가 아닐 때만 일치한다("bic" 은 "public" 안에서 안 맞음).
#pragma once

#include <cstdint>
#include <map>
#include <span>
#include <string_view>
#include <vector>

#include "prompt_airlock/detect/view.hpp"

namespace prompt_airlock::detect {

struct TermHit {
    std::uint32_t first_unit;
    std::uint32_t last_unit;
    std::uint32_t term;  // make 에 넘긴 목록의 순번
};

class TermMatcher {
public:
    // 단어는 이미 NFKC 인 UTF-32 다. 공백만 있거나 빈 단어는 무시한다.
    [[nodiscard]] static TermMatcher make(std::span<const std::u32string_view> terms);
    [[nodiscard]] std::vector<TermHit> find(const DetectionView& view) const;
    [[nodiscard]] bool empty() const noexcept { return nodes_.size() <= 1; }

private:
    struct Node {
        std::map<char32_t, std::uint32_t> next;
        std::uint32_t fail = 0;
        std::uint32_t output_link = 0;          // 같은 상태에서 끝나는 더 짧은 단어 노드(없으면 0)
        std::vector<std::uint32_t> terms;       // 이 노드에서 끝나는 단어 순번
        std::uint32_t length = 0;               // 공백을 뺀 단어 길이(글자 수)
    };
    std::vector<Node> nodes_{Node{}};
};

// 단어 일치에서 건너뛰는 공백류. NFKC 뒤 기준.
[[nodiscard]] constexpr bool is_term_space(char32_t c) noexcept { return c == U' ' || c == U'\t'; }

}  // namespace prompt_airlock::detect
