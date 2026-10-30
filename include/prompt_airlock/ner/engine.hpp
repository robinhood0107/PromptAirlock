// NER 엔진(ADR 0006, 0007): 탐지용 보기 한 구간 → 원문 byte 로 돌려준 PERSON·ORGANIZATION 탐지 결과.
// 흐름: tokenize → 추론 → argmax → BIO 결합 → 인접 병합 → 경계 다듬기(boundary.hpp) → 원문 구간.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
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

// 모델 한 번의 입력 한도(special token 2개 포함). detect 는 넘으면 자르지 않고 거부하고, detect_all 은 창으로 나눈다.
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
    TooManyWindows,  // detect_all 의 창이 max_ner_windows 를 넘는다
    Stopped,         // detect_all 이 창 사이에서 중단 신호를 봤다
};

// 모델 label 하나의 해석. type 이 없으면 O 또는 관심 밖 label 이다.
struct NerLabel {
    std::optional<core::EntityType> type;
    bool begin = false;
};

class NerEngine {
public:
    // dir 의 세 파일이 고정 해시와 같고 모델을 읽을 수 있어야 한다. 아니면 DetectError::Unavailable.
    // 엔진 하나짜리 편의 함수라 ORT 환경을 따로 만든다. 여러 엔진은 아래 함수로 환경을 함께 쓴다.
    [[nodiscard]] static std::expected<NerEngine, core::DetectError> make(const std::filesystem::path& dir);
    [[nodiscard]] static std::expected<NerEngine, core::DetectError> make(const VerifiedModelFiles& files,
                                                                          std::shared_ptr<const OrtEnv> env);

    // text 는 view 를 만든 원문, segment 는 그 순번이다. 결과는 위치 순이며 모두 DetectorKind::Ner 다.
    // 한 세션은 한 번에 한 스레드만 쓰므로 호출자가 직렬화한다.
    [[nodiscard]] std::expected<std::vector<core::EntitySpan>, NerError> detect(
        std::string_view text, core::SegmentIndex segment, const detect::DetectionView& view, ViewRange range);

    // 보기 전체. 길면 문장 창(windows.hpp)으로 나눠 창마다 추론하고, 겹친 창에서 같은 결과는 하나만 남긴다.
    // 겹친 창이 같은 이름을 다른 길이로 찾으면 둘 다 남는다(정책 단계의 merge_entities 가 넓은 쪽으로 합친다).
    // 창마다 추론 전에 stop 을 본다. 추론 한 번(256 token p95 32 ms)은 끝까지 돈다(ORT 의 중단 플래그는 원자 변수가 아니라 쓰지 않는다).
    [[nodiscard]] std::expected<std::vector<core::EntitySpan>, NerError> detect_all(
        std::string_view text, core::SegmentIndex segment, const detect::DetectionView& view,
        std::stop_token stop = {});

private:
    NerEngine(WordPieceTokenizer tokenizer, OrtSession session, std::vector<NerLabel> labels);

    // body 는 special 을 뺀 토큰이고 위치는 보기의 base 부터 센다. 찾은 결과를 out 에 더한다.
    [[nodiscard]] std::expected<void, NerError> infer(std::string_view text, core::SegmentIndex segment,
                                                      const detect::DetectionView& view, std::uint32_t base,
                                                      std::span<const Token> body, std::int64_t cls, std::int64_t sep,
                                                      std::vector<core::EntitySpan>& out);

    WordPieceTokenizer tokenizer_;
    OrtSession session_;
    std::vector<NerLabel> labels_;
};

}  // namespace prompt_airlock::ner
