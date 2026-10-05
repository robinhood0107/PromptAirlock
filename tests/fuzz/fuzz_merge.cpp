// 무작위 탐지 결과 목록으로 merge 불변식(정렬, 비겹침, 포함, 합집합 보존)을 확인한다.
#include "prompt_airlock/core/merge.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pc = prompt_airlock::core;

namespace {

constexpr std::size_t text_size = 80;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string text(text_size, 'x');
    std::vector<pc::EntitySpan> input;
    // 4 byte 마다 탐지 결과 하나: segment, 시작, 길이, 종류.
    for (std::size_t i = 0; i + 4 <= size && input.size() < 600; i += 4) {
        const auto segment = pc::SegmentIndex{static_cast<std::uint32_t>(data[i] % 3)};
        const std::size_t begin = data[i + 1] % (text_size - 1);
        const std::size_t end = std::min(text_size, begin + 1 + data[i + 2] % 16);
        const auto type = static_cast<pc::EntityType>(data[i + 3] % pc::entity_type_count);
        const auto detector = static_cast<pc::DetectorKind>((data[i + 3] >> 5U) % 6);
        const auto span = pc::ByteSpan::make(pc::Utf8ByteOffset{begin}, pc::Utf8ByteOffset{end});
        const auto entity = pc::EntitySpan::make(text, segment, *span, type, detector);
        if (!entity) {
            __builtin_trap();
        }
        input.push_back(*entity);
    }

    const auto out = pc::merge_entities(input);
    for (std::size_t k = 1; k < out.size(); ++k) {
        const bool ordered = out[k - 1].segment < out[k].segment ||
                             (out[k - 1].segment == out[k].segment && out[k - 1].span.end() <= out[k].span.begin());
        if (!ordered) {
            __builtin_trap();
        }
    }
    for (const auto& entity : input) {
        const auto owners = std::count_if(out.begin(), out.end(), [&](const pc::MergedEntity& m) {
            return m.segment == entity.segment() && m.span.contains(entity.span());
        });
        if (owners != 1) {
            __builtin_trap();
        }
    }
    for (const auto& merged : out) {
        if (!merged.types.contains(merged.label_type) || pc::default_action(merged.label_type) != merged.action) {
            __builtin_trap();
        }
    }
    return 0;
}
