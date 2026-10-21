// 문서 단위 탐지 입구. 결과 위치는 각 segment 원문 byte 이고, 판정(차단·가명화)은 core 가 한다.
#pragma once

#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "prompt_airlock/core/document.hpp"
#include "prompt_airlock/core/encoded.hpp"
#include "prompt_airlock/core/entity.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/detect/ner_scanner.hpp"
#include "prompt_airlock/detect/sensitive.hpp"
#include "prompt_airlock/detect/terms.hpp"

namespace prompt_airlock::detect {

struct DocumentDetection {
    // core::max_entities 를 넘으면 max_entities + 1 개에서 멈춘다(check_policy 가 TooManyEntities 로 거절).
    std::vector<core::EntitySpan> entities;
    // 인코딩 덩어리. 판정은 core judge_encoded(잔여 검사 verify_residual 이 필수로 부른다).
    std::vector<core::EncodedFinding> encoded;
    // 개인 표지 없이 통과한 민감정보 범주 문장 수(감사용).
    SensitiveTally sensitive_passed;
};

// 불변. 만든 뒤에는 const 로만 쓰므로 여러 요청이 함께 읽어도 된다.
class Detectors {
public:
    // 기관 보호어(Phase 8 설정이 넘긴다). UTF-8 이 아니면 InvalidUtf8, 정규화 뒤 비면 EmptyContent.
    // ner 가 있으면 segment 마다(인코딩을 푼 텍스트와 잔여 검사 포함) 사람·기관 이름도 찾는다.
    // 비워 두면 NER 없이 결정론 규칙만 돈다(시험용). 제품 조립은 항상 NerPool 을 넘긴다.
    [[nodiscard]] static std::expected<Detectors, core::InputError> make(std::span<const std::string_view> internal_terms,
                                                                         std::shared_ptr<const NerScanner> ner = {});

    [[nodiscard]] std::expected<DocumentDetection, core::DetectError> detect(const core::PromptDocument& document) const;

    // segment 하나. 시험과 잔여 검사에서도 쓴다.
    [[nodiscard]] std::expected<std::vector<core::EntitySpan>, core::DetectError> detect_segment(
        std::string_view text, core::SegmentIndex segment) const;

private:
    Detectors(TermMatcher internal_terms, std::shared_ptr<const NerScanner> ner);
    [[nodiscard]] std::expected<std::vector<core::EntitySpan>, core::DetectError> scan(
        std::string_view text, core::SegmentIndex segment, SensitiveTally& tally) const;
    // 덩어리를 깊이 2까지 풀고 푼 결과를 같은 탐지기로 본다.
    [[nodiscard]] std::expected<std::vector<core::EncodedFinding>, core::DetectError> scan_encoded(
        std::string_view text, core::SegmentIndex segment) const;
    TermMatcher internal_terms_;
    std::shared_ptr<const NerScanner> ner_;  // 여러 Detectors 사본이 같은 pool 을 함께 쓴다
    TermMatcher account_context_;   // 계좌 문맥어(data/account_context_terms.hpp)
    TermMatcher secret_markers_;    // 인증 표지어(data/credential_markers.hpp)
    TermMatcher user_markers_;
    TermMatcher account_markers_;
    TermMatcher sensitive_categories_;  // data/sensitive_category_terms.hpp 순서
    TermMatcher honorifics_;
    TermMatcher self_statements_;
};

}  // namespace prompt_airlock::detect
