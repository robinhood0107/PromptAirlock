// 아무 바이트를 넣어도 죽지 않고, 탐지 결과 위치가 원문의 글자 경계 안에 있으며, 두 번 돌려도 같다.
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/utf8.hpp"
#include "prompt_airlock/detect/detectors.hpp"

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    static const auto detectors = *pd::Detectors::make(std::vector<std::string_view>{"가상기관", "acme"});
    const auto first = detectors.detect_segment(text, pc::SegmentIndex{0});
    if (!first) {
        return 0;
    }
    for (const auto& entity : *first) {
        if (!pc::check_span(text, entity.span())) {
            __builtin_trap();
        }
    }
    const auto second = detectors.detect_segment(text, pc::SegmentIndex{0});
    if (!second || *second != *first) {
        __builtin_trap();
    }
    return 0;
}
