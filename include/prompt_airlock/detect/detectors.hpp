// 문서 단위 탐지 입구. 결과 위치는 각 segment 원문 byte 이고, 판정(차단·가명화)은 core 가 한다.
#pragma once

#include <expected>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "prompt_airlock/core/document.hpp"
#include "prompt_airlock/core/entity.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/detect/terms.hpp"

namespace prompt_airlock::detect {

struct DocumentDetection {
    // core::max_entities 를 넘으면 max_entities + 1 개에서 멈춘다(check_policy 가 TooManyEntities 로 거절).
    std::vector<core::EntitySpan> entities;
};

// 불변. 만든 뒤에는 const 로만 쓰므로 여러 요청이 함께 읽어도 된다.
class Detectors {
public:
    // 기관 보호어(Phase 8 설정이 넘긴다). UTF-8 이 아니면 InvalidUtf8, 정규화 뒤 비면 EmptyContent.
    [[nodiscard]] static std::expected<Detectors, core::InputError> make(std::span<const std::string_view> internal_terms);

    [[nodiscard]] std::expected<DocumentDetection, core::DetectError> detect(const core::PromptDocument& document) const;

    // segment 하나. 시험과 잔여 검사에서도 쓴다.
    [[nodiscard]] std::expected<std::vector<core::EntitySpan>, core::DetectError> detect_segment(
        std::string_view text, core::SegmentIndex segment) const;

private:
    explicit Detectors(TermMatcher internal_terms) noexcept : internal_terms_(std::move(internal_terms)) {}
    TermMatcher internal_terms_;
};

}  // namespace prompt_airlock::detect
