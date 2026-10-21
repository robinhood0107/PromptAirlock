// NER 엔진(ADR 0006, 0007): 탐지용 보기 한 구간 → 원문 byte 로 돌려준 PERSON·ORGANIZATION 탐지 결과.
// 흐름: tokenize → 추론 → argmax → BIO 결합 → 인접 병합 → 조사 후처리 → 원문 구간.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/entity.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/types.hpp"
#include "prompt_airlock/detect/view.hpp"
#include "prompt_airlock/ner/model_files.hpp"
#include "prompt_airlock/ner/session.hpp"
#include "prompt_airlock/ner/tokenizer.hpp"

namespace prompt_airlock::ner {

// 모델 한 번의 입력 한도(special token 2개 포함). 넘으면 자르지 않고 거부한다. 분할은 Phase 7-2.
inline constexpr std::size_t max_ner_tokens = 512;

// 보기 안의 반열린 구간 [first, end).
struct ViewRange {
    std::uint32_t first;
    std::uint32_t end;
};

enum class NerError : std::uint8_t {
    InputTooLong,  // 토큰이 max_ner_tokens 를 넘는다
    Unavailable,   // 추론 실패, 출력 모양 불일치
    InvalidSpan,   // 구간이 보기 밖이거나 탐지 결과가 원문과 맞지 않는다
};

// 모델 label 하나의 해석. type 이 없으면 O 또는 관심 밖 label 이다.
struct NerLabel {
    std::optional<core::EntityType> type;
    bool begin = false;
};

class NerEngine {
public:
    // dir 의 세 파일이 고정 해시와 같고 모델을 읽을 수 있어야 한다. 아니면 DetectError::Unavailable.
    [[nodiscard]] static std::expected<NerEngine, core::DetectError> make(const std::filesystem::path& dir);
    [[nodiscard]] static std::expected<NerEngine, core::DetectError> make(const VerifiedModelFiles& files);

    // text 는 view 를 만든 원문, segment 는 그 순번이다. 결과는 위치 순이며 모두 DetectorKind::Ner 다.
    // 한 세션은 한 번에 한 스레드만 쓰므로 호출자가 직렬화한다.
    [[nodiscard]] std::expected<std::vector<core::EntitySpan>, NerError> detect(
        std::string_view text, core::SegmentIndex segment, const detect::DetectionView& view, ViewRange range);

private:
    NerEngine(WordPieceTokenizer tokenizer, OrtSession session, std::vector<NerLabel> labels);

    WordPieceTokenizer tokenizer_;
    OrtSession session_;
    std::vector<NerLabel> labels_;
};

}  // namespace prompt_airlock::ner
