#include "pipeline.hpp"

#include <chrono>
#include <fstream>

#include <nlohmann/json.hpp>

namespace prompt_airlock::ner {

Pipeline::Pipeline(Candidate c, std::unique_ptr<const Tokenizer> t, NerModel m, std::vector<std::string> id2label,
                   NormPolicy norm)
    : candidate_(std::move(c)), tokenizer_(std::move(t)), model_(std::move(m)), id2label_(std::move(id2label)),
      labels_(build_label_table(id2label_, candidate_.entity_map)), norm_(norm) {}

std::expected<Pipeline, std::string> Pipeline::load(Ort::Env& env, const Candidate& c,
                                                    const std::filesystem::path& root, NormPolicy norm) {
  using Clock = std::chrono::steady_clock;
  const auto t0 = Clock::now();
  auto tok = load_tokenizer(root / c.tokenizer);
  const auto t1 = Clock::now();
  if (!tok) return std::unexpected("tokenizer: " + std::string(to_string(tok.error())));
  std::vector<std::string> id2label;
  try {
    std::ifstream in(root / c.config, std::ios::binary);
    if (!in) return std::unexpected("config: cannot open");
    const auto j = nlohmann::json::parse(in);
    const auto& m = j.at("id2label");
    id2label.resize(m.size());
    for (const auto& [k, v] : m.items()) {
      const auto idx = static_cast<std::size_t>(std::stoul(k));
      if (idx >= id2label.size()) return std::unexpected("config: id2label hole");
      id2label[idx] = v.get<std::string>();
    }
  } catch (const std::exception& ex) {
    return std::unexpected(std::string("config: ") + ex.what());
  }
  const auto t2 = Clock::now();
  auto model = NerModel::load(env, root / c.onnx, c.max_tokens);
  if (!model) return std::unexpected("model: " + std::string(to_string(model.error())));
  const auto t3 = Clock::now();
  Pipeline p(c, std::move(*tok), std::move(*model), std::move(id2label), norm);
  p.timings_.tokenizer_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
  p.timings_.session_ms = std::chrono::duration<double, std::milli>(t3 - t2).count();
  return p;
}

std::expected<Analysis, PipelineError> Pipeline::analyze(std::string_view original) {
  Analysis a;
  auto norm = normalize(original, norm_);
  if (!norm) return std::unexpected(PipelineError::Text);
  a.normalized = std::move(*norm);
  a.tokens = tokenizer_->encode(a.normalized);
  if (a.tokens.size() > model_.max_tokens()) return std::unexpected(PipelineError::InputTooLong);
  std::vector<std::int64_t> ids;
  ids.reserve(a.tokens.size());
  for (const auto& t : a.tokens) ids.push_back(t.id);
  auto logits = model_.run(ids);
  if (!logits) return std::unexpected(PipelineError::Model);
  if (logits->num_labels != labels_.size()) return std::unexpected(PipelineError::Model);
  for (std::size_t i = 0; i < logits->seq_len; ++i) a.label_ids.push_back(logits->argmax(i));
  a.raw = decode_entities(a.tokens, *logits, labels_, original, candidate_.decode);
  a.post = strip_trailing_particles(a.raw, a.normalized);
  return a;
}

std::string_view to_string(PipelineError e) {
  switch (e) {
    case PipelineError::Text: return "text";
    case PipelineError::InputTooLong: return "input-too-long";
    case PipelineError::Model: return "model";
  }
  return "unknown";
}

}  // namespace prompt_airlock::ner
