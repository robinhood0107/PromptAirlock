#pragma once

#include <compare>
#include <expected>
#include <string_view>

#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// 탐지 결과 한 건. 표현 불변식(spec §6): start < end, 구간이 segment 텍스트 안, 문자 경계, 종류가 유효.
// make 로만 만들며, 정책 검사는 문서와 다시 대조한다(detector 를 믿지 않는다).
class EntitySpan {
public:
    [[nodiscard]] static std::expected<EntitySpan, InputError> make(std::string_view segment_text,
                                                                    SegmentIndex segment, ByteSpan span,
                                                                    EntityType type, DetectorKind detector) noexcept;

    [[nodiscard]] constexpr SegmentIndex segment() const noexcept { return segment_; }
    [[nodiscard]] constexpr ByteSpan span() const noexcept { return span_; }
    [[nodiscard]] constexpr EntityType type() const noexcept { return type_; }
    [[nodiscard]] constexpr DetectorKind detector() const noexcept { return detector_; }

    // 멤버 선언 순서가 정렬 순서다: segment, 구간, 종류, detector.
    constexpr auto operator<=>(const EntitySpan&) const noexcept = default;

private:
    constexpr EntitySpan(SegmentIndex segment, ByteSpan span, EntityType type, DetectorKind detector) noexcept
        : segment_(segment), span_(span), type_(type), detector_(detector) {}

    SegmentIndex segment_;
    ByteSpan span_;
    EntityType type_;
    DetectorKind detector_;
};

}  // namespace prompt_airlock::core
