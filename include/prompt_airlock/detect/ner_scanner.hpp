// 탐지기가 쓰는 NER 입구(Phase 7-2). detect 는 ONNX Runtime 을 모르고 이 입구만 안다.
// 실제 구현은 ner 모듈의 NerPool 이고, 시험은 가짜를 끼운다.
#pragma once

#include <expected>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/entity.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/types.hpp"
#include "prompt_airlock/detect/view.hpp"

namespace prompt_airlock::detect {

class NerScanner {
public:
    NerScanner() = default;
    NerScanner(const NerScanner&) = delete;
    NerScanner& operator=(const NerScanner&) = delete;
    virtual ~NerScanner() = default;

    // view 는 text 의 탐지용 보기다. 결과는 원문 byte 이고 종류는 Person, Organization 뿐이다.
    // 여러 요청 스레드가 함께 부른다. 장애는 Unavailable, 대기열 포화와 창 수 초과는 Overloaded 다.
    [[nodiscard]] virtual std::expected<std::vector<core::EntitySpan>, core::DetectError> scan(
        std::string_view text, core::SegmentIndex segment, const DetectionView& view) const = 0;
};

}  // namespace prompt_airlock::detect
