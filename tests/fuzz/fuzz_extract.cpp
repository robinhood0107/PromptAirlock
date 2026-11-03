// 문서 추출(ADR 0028): 아무 byte 를 넣어도 죽지 않고, 성공하면 모든 글자가 올바른 UTF-8 이며 출력 상한 안이다.
// 첫 byte 로 확장자 힌트를 고르고 나머지가 파일이다. zip·XML 경로는 사전(fuzz_extract.dict)이 시작 재료를 준다.
// 첫 byte 가 0xF0 이상이면 나머지를 hwp 5.0 본문 스트림으로 보고 CFB 로 감싼다(바이너리 seed 를 올릴 수 없어서,
// 레코드·문단 글자 해석까지 바로 닿게 함). 끝 bit 가 1 이면 압축 문서로 표시해 deflate 풀기도 지난다.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "hwp_writer.hpp"
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
    const std::string_view rest(reinterpret_cast<const char*>(data + 1), size - 1);
    const bool wrap_hwp = data[0] >= 0xF0 && rest.size() <= 60 * 1024;  // FAT 섹터 하나(126 섹터) 안
    const std::string file = wrap_hwp ? pa_test::hwp::hwp(data[0] & 1U, std::string(rest)) : std::string(rest);
    const auto result = ex::extract(std::as_bytes(std::span(file.data(), file.size())),
                                    wrap_hwp ? std::string_view("hwp") : hints[data[0] % hints.size()], limits);
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
