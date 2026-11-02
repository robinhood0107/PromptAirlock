// 문서 추출(ADR 0028): 아무 byte 를 넣어도 죽지 않고, 성공하면 모든 글자가 올바른 UTF-8 이며 출력 상한 안이다.
// 첫 byte 로 확장자 힌트를 고르고 나머지가 파일이다. zip·XML 경로는 사전(fuzz_extract.dict)이 시작 재료를 준다.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "prompt_airlock/core/utf8.hpp"
#include "prompt_airlock/extract/document.hpp"

namespace ex = prompt_airlock::extract;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    static constexpr std::array<std::string_view, 8> hints = {"", "txt", "csv", "htm", "md", "docx", "hwp", "zip"};
    ex::ExtractLimits limits;
    limits.output_bytes = 1U << 20;  // fuzz 속도를 위해 줄임
    limits.total_bytes = 4U << 20;
    const auto file = std::as_bytes(std::span(data + 1, size - 1));
    const auto result = ex::extract(file, hints[data[0] % hints.size()], limits);
    if (!result) {
        return 0;
    }
    std::size_t total = 0;
    for (const auto& b : result->blocks) {
        total += b.text.size();
        if (!prompt_airlock::core::validate_utf8(b.text) || !prompt_airlock::core::validate_utf8(b.where)) {
            __builtin_trap();
        }
    }
    if (total > limits.output_bytes || result->blocks.empty()) {
        __builtin_trap();
    }
    return 0;
}
