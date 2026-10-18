#include "prompt_airlock/detect/terms.hpp"

#include <deque>

#include "prompt_airlock/detect/scan.hpp"

namespace prompt_airlock::detect {

TermMatcher TermMatcher::make(std::span<const std::u32string_view> terms) {
    TermMatcher m;
    for (std::uint32_t t = 0; t < terms.size(); ++t) {
        std::uint32_t node = 0;
        std::uint32_t length = 0;
        for (const char32_t raw : terms[t]) {
            if (is_term_space(raw)) {
                continue;
            }
            const char32_t c = ascii_lower(raw);
            const auto it = m.nodes_[node].next.find(c);
            if (it != m.nodes_[node].next.end()) {
                node = it->second;
            } else {
                const auto created = static_cast<std::uint32_t>(m.nodes_.size());
                m.nodes_[node].next.emplace(c, created);
                m.nodes_.push_back(Node{});
                node = created;
            }
            ++length;
        }
        if (length > 0) {
            m.nodes_[node].terms.push_back(t);
            m.nodes_[node].length = length;
        }
    }
    // 너비 우선으로 실패 링크와 출력 링크를 만든다.
    std::deque<std::uint32_t> queue;
    for (const auto& [c, child] : m.nodes_[0].next) {
        queue.push_back(child);
    }
    while (!queue.empty()) {
        const auto node = queue.front();
        queue.pop_front();
        for (const auto& [c, child] : m.nodes_[node].next) {
            std::uint32_t f = m.nodes_[node].fail;
            while (f != 0 && !m.nodes_[f].next.contains(c)) {
                f = m.nodes_[f].fail;
            }
            const auto it = m.nodes_[f].next.find(c);
            const std::uint32_t target = it != m.nodes_[f].next.end() && it->second != child ? it->second : 0;
            m.nodes_[child].fail = target;
            m.nodes_[child].output_link = m.nodes_[target].terms.empty() ? m.nodes_[target].output_link : target;
            queue.push_back(child);
        }
    }
    return m;
}

std::vector<TermHit> TermMatcher::find(const DetectionView& view) const {
    std::vector<TermHit> hits;
    if (empty()) {
        return hits;
    }
    // 공백을 뺀 글자들의 보기 위치. 일치한 단어의 시작 위치를 되돌리는 데 쓴다.
    std::vector<std::uint32_t> positions;
    positions.reserve(view.units.size());
    std::uint32_t node = 0;
    for (std::uint32_t i = 0; i < view.units.size(); ++i) {
        const char32_t raw = view.units[i].value;
        if (is_term_space(raw)) {
            continue;
        }
        positions.push_back(i);
        const char32_t c = ascii_lower(raw);
        while (node != 0 && !nodes_[node].next.contains(c)) {
            node = nodes_[node].fail;
        }
        const auto it = nodes_[node].next.find(c);
        node = it != nodes_[node].next.end() ? it->second : 0;
        for (std::uint32_t out = nodes_[node].terms.empty() ? nodes_[node].output_link : node; out != 0;
             out = nodes_[out].output_link) {
            const auto first = positions[positions.size() - nodes_[out].length];
            const auto& u = view.units;
            const bool open = !is_ascii_alnum(u[first].value) || first == 0 || !is_ascii_alnum(u[first - 1].value);
            const bool close = !is_ascii_alnum(raw) || i + 1 == u.size() || !is_ascii_alnum(u[i + 1].value);
            if (!open || !close) {
                continue;
            }
            for (const auto term : nodes_[out].terms) {
                hits.push_back({first, i, term});
            }
        }
    }
    return hits;
}

}  // namespace prompt_airlock::detect
