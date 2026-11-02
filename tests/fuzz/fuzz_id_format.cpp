// 기관 형식 마스크(ADR 0027): 아무 마스크와 글을 넣어도 죽지 않고, 받은 마스크로 찾은 위치는 원문 글자 경계 안에 있다.
// 첫 줄바꿈 앞이 마스크, 뒤가 글이다(텍스트 seed 로 시작할 수 있게).
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/utf8.hpp"
#include "prompt_airlock/detect/detectors.hpp"

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view input(reinterpret_cast<const char*>(data), size);
    const auto cut = input.find('\n');
    if (cut == std::string_view::npos) {
        return 0;
    }
    const auto mask = input.substr(0, cut);
    const auto text = input.substr(cut + 1);
    const auto format = pd::IdFormat::parse(mask);
    if (!format) {
        return 0;
    }
    if (format->size() > pd::max_id_format_length) {
        __builtin_trap();
    }
    pd::InstitutionPolicy policy;
    policy.id_formats.push_back(*format);
    const auto detectors = pd::Detectors::make({}, {}, policy);
    if (!detectors) {
        __builtin_trap();
    }
    const auto found = detectors->detect_segment(text, pc::SegmentIndex{0});
    if (!found) {
        return 0;
    }
    for (const auto& entity : *found) {
        if (!pc::check_span(text, entity.span())) {
            __builtin_trap();
        }
    }
    return 0;
}
