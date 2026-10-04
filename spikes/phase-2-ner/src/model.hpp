#pragma once
// ONNX Runtime token-classification 세션. ORT 예외는 이 경계에서 값으로 바꾼다.
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <onnxruntime_cxx_api.h>

namespace prompt_airlock::ner {

enum class ModelError { Load, Run, BadOutput, InputTooLong };

struct Logits {
  std::size_t seq_len{};
  std::size_t num_labels{};
  std::vector<float> data;  // [seq_len, num_labels] row-major
  [[nodiscard]] std::size_t argmax(std::size_t pos) const;
};

class NerModel {
 public:
  // CPU, intra/inter-op 1 thread, 순차 실행.
  [[nodiscard]] static std::expected<NerModel, ModelError> load(Ort::Env& env,
                                                                const std::filesystem::path& onnx,
                                                                std::size_t max_tokens);
  [[nodiscard]] std::expected<Logits, ModelError> run(std::span<const std::int64_t> ids);
  [[nodiscard]] const std::vector<std::string>& input_names() const { return input_names_; }
  [[nodiscard]] std::size_t max_tokens() const { return max_tokens_; }

 private:
  std::unique_ptr<Ort::Session> session_;
  std::vector<std::string> input_names_;
  std::string output_name_;
  std::size_t max_tokens_{};
};

[[nodiscard]] std::string_view to_string(ModelError e);

}  // namespace prompt_airlock::ner
