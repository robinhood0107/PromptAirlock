// 인코딩 후보 찾기와 풀기: 아무 바이트에도 죽지 않고, 후보는 원문 안에 있으며, 풀린 결과의 텍스트 판정이 엄격 UTF-8 과 맞는다.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "prompt_airlock/core/utf8.hpp"
#include "prompt_airlock/detect/encoded.hpp"

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    for (const auto& c : pd::encoded_candidates(text)) {
        if (c.source.end().value() > text.size()) {
            __builtin_trap();
        }
        const auto decoded = pd::decode(text.substr(c.source.begin().value(), c.source.size()), c.kind);
        if (decoded && pd::is_text(*decoded) && !pc::validate_utf8(*decoded)) {
            __builtin_trap();
        }
    }
    return 0;
}
