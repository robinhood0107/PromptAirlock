#include "model.hpp"

#include <algorithm>
#include <array>

namespace prompt_airlock::ner {

std::size_t Logits::argmax(std::size_t pos) const {
  const auto* row = data.data() + pos * num_labels;
  return static_cast<std::size_t>(std::max_element(row, row + num_labels) - row);
}

std::expected<NerModel, ModelError> NerModel::load(Ort::Env& env, const std::filesystem::path& onnx,
                                                   std::size_t max_tokens) {
  try {
    Ort::SessionOptions opts;
    opts.SetIntraOpNumThreads(1);
    opts.SetInterOpNumThreads(1);
    opts.SetExecutionMode(ExecutionMode::ORT_SEQUENTIAL);
    opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
    NerModel m;
    m.session_ = std::make_unique<Ort::Session>(env, onnx.c_str(), opts);
    Ort::AllocatorWithDefaultOptions alloc;
    for (std::size_t i = 0; i < m.session_->GetInputCount(); ++i)
      m.input_names_.emplace_back(m.session_->GetInputNameAllocated(i, alloc).get());
    if (m.session_->GetOutputCount() < 1) return std::unexpected(ModelError::BadOutput);
    m.output_name_ = m.session_->GetOutputNameAllocated(0, alloc).get();
    for (const auto& n : m.input_names_)
      if (n != "input_ids" && n != "attention_mask" && n != "token_type_ids")
        return std::unexpected(ModelError::Load);  // 모르는 입력 계약은 거부
    m.max_tokens_ = max_tokens;
    return m;
  } catch (const Ort::Exception&) {
    return std::unexpected(ModelError::Load);
  }
}

std::expected<Logits, ModelError> NerModel::run(std::span<const std::int64_t> ids) {
  if (ids.size() > max_tokens_) return std::unexpected(ModelError::InputTooLong);  // 자르지 않고 거부
  try {
    const auto n = static_cast<std::int64_t>(ids.size());
    const std::array<std::int64_t, 2> shape{1, n};
    std::vector<std::int64_t> input_ids(ids.begin(), ids.end());
    std::vector<std::int64_t> mask(ids.size(), 1);
    std::vector<std::int64_t> types(ids.size(), 0);
    const auto mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
    std::vector<Ort::Value> values;
    std::vector<const char*> names;
    for (const auto& name : input_names_) {
      auto& buf = name == "input_ids" ? input_ids : name == "attention_mask" ? mask : types;
      values.push_back(Ort::Value::CreateTensor<std::int64_t>(mem, buf.data(), buf.size(), shape.data(), shape.size()));
      names.push_back(name.c_str());
    }
    const char* out_name = output_name_.c_str();
    auto outputs = session_->Run(Ort::RunOptions{nullptr}, names.data(), values.data(), values.size(), &out_name, 1);
    const auto info = outputs.front().GetTensorTypeAndShapeInfo();
    const auto oshape = info.GetShape();
    if (oshape.size() != 3 || oshape[0] != 1 || oshape[1] != n || oshape[2] <= 0)
      return std::unexpected(ModelError::BadOutput);
    Logits l;
    l.seq_len = ids.size();
    l.num_labels = static_cast<std::size_t>(oshape[2]);
    const float* p = outputs.front().GetTensorData<float>();
    l.data.assign(p, p + l.seq_len * l.num_labels);
    return l;
  } catch (const Ort::Exception&) {
    return std::unexpected(ModelError::Run);
  }
}

std::string_view to_string(ModelError e) {
  switch (e) {
    case ModelError::Load: return "load";
    case ModelError::Run: return "run";
    case ModelError::BadOutput: return "bad-output";
    case ModelError::InputTooLong: return "input-too-long";
  }
  return "unknown";
}

}  // namespace prompt_airlock::ner
