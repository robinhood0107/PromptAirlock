// 측정 도구가 함께 쓰는 문장 나누기. 마침표·물음표·느낌표·줄바꿈 뒤(다음이 공백·줄바꿈이거나 끝)에서 나누고 빈 문장은 버린다.
#pragma once

#include <string>
#include <vector>

inline std::vector<std::string> split_sentences(const std::string& text) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        cur.push_back(c);
        const bool end = c == '.' || c == '?' || c == '!' || c == '\n';
        if (end && (i + 1 == text.size() || text[i + 1] == ' ' || text[i + 1] == '\n')) {
            if (cur.find_first_not_of(" \n") != std::string::npos) {
                out.push_back(cur);
            }
            cur.clear();
        }
    }
    if (cur.find_first_not_of(" \n") != std::string::npos) {
        out.push_back(cur);
    }
    return out;
}
