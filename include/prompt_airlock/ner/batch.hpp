#pragma once

#include <cstdint>
#include <vector>

#include "prompt_airlock/ner/tokenizer.hpp"
#include "prompt_airlock/ner/windows.hpp"

namespace prompt_airlock::ner {

inline constexpr std::size_t document_batch_windows = 64;

// 토큰의 보기 위치는 문서 전체 기준이다. 모델 입력과 창만 배치마다 복사한다.
struct TokenBatch {
    std::vector<Token> tokens;
    std::vector<TokenWindow> windows;
    std::int64_t cls = 0;
    std::int64_t sep = 0;
};

}  // namespace prompt_airlock::ner
