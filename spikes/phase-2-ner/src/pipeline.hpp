#pragma once
// 원문 → 정규화 → tokenizer → ORT → label decode → 원문 바이트 span.
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "candidates.hpp"
#include "decode.hpp"
#include "model.hpp"
#include "text.hpp"
#include "tokenizer.hpp"

namespace prompt_airlock::ner {

struct Analysis {
  std::vector<Unit> normalized;
  std::vector<Token> tokens;
  std::vector<std::size_t> label_ids;  // 토큰별 argmax label (진단용)
  std::vector<EntitySpan> raw;   // 모델 출력 그대로
  std::vector<EntitySpan> post;  // 조사 후처리 적용
};

struct LoadTimings {
  double tokenizer_ms = 0;  // tokenizer.json 파싱
  double session_ms = 0;    // ORT 세션 생성
};

enum class PipelineError { Text, InputTooLong, Model };

class Pipeline {
 public:
  [[nodiscard]] static std::expected<Pipeline, std::string> load(Ort::Env& env, const Candidate& c,
                                                                 const std::filesystem::path& model_root,
                                                                 NormPolicy norm = {});
  // 어떤 단계든 실패하면 entity 없이 오류를 돌려준다(호출자는 fail-closed 로 처리).
  [[nodiscard]] std::expected<Analysis, PipelineError> analyze(std::string_view original);
  [[nodiscard]] const Tokenizer& tokenizer() const { return *tokenizer_; }
  [[nodiscard]] const Candidate& candidate() const { return candidate_; }
  [[nodiscard]] const std::vector<std::string>& id2label() const { return id2label_; }
  [[nodiscard]] const NerModel& model() const { return model_; }
  [[nodiscard]] const LoadTimings& load_timings() const { return timings_; }
  [[nodiscard]] NormPolicy norm_policy() const { return norm_; }

 private:
  Pipeline(Candidate c, std::unique_ptr<const Tokenizer> t, NerModel m, std::vector<std::string> id2label,
           NormPolicy norm);
  Candidate candidate_;
  std::unique_ptr<const Tokenizer> tokenizer_;
  NerModel model_;
  std::vector<std::string> id2label_;
  std::vector<LabelInfo> labels_;
  NormPolicy norm_;
  LoadTimings timings_;
};

[[nodiscard]] std::string_view to_string(PipelineError e);

}  // namespace prompt_airlock::ner
