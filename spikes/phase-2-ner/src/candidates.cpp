#include "candidates.hpp"

namespace prompt_airlock::ner {

const std::vector<Candidate>& candidates() {
  using enum EntityType;
  static const std::vector<Candidate> list = {
      {"koelectra-small-pii", "atonlee/koelectra-ko-pii-ner", "1e75c01e707232401883cf364151bbe2e560c708",
       "atonlee_koelectra-ko-pii-ner/onnx/model.onnx", "atonlee_koelectra-ko-pii-ner/tokenizer.json",
       "atonlee_koelectra-ko-pii-ner/config.json", {{"NAME", Person}, {"ORGANIZATION", Organization}}, {}},
      {"koelectra-small-pii-int8", "atonlee/koelectra-ko-pii-ner", "1e75c01e707232401883cf364151bbe2e560c708",
       "atonlee_koelectra-ko-pii-ner/onnx/model_int8.onnx", "atonlee_koelectra-ko-pii-ner/tokenizer.json",
       "atonlee_koelectra-ko-pii-ner/config.json", {{"NAME", Person}, {"ORGANIZATION", Organization}}, {}},
      {"veil-ko-lite-int8", "1T/veil-pii-ko-lite", "dd26d2b1ca189f9c819a783f75e944e4baf22050",
       "1T_veil-pii-ko-lite/model.int8.onnx", "1T_veil-pii-ko-lite/tokenizer.json", "1T_veil-pii-ko-lite/config.json",
       {{"PERSON", Person}, {"ORGANIZATION", Organization}}, {}},
      {"nym-mmbert-small-int8", "Wismut/nym-pii-multilingual-small", "4348999cd3c2e20c49615e9af7c6bbb45b64cd85",
       "Wismut_nym-pii-multilingual-small/int8/model_int8.onnx",
       "Wismut_nym-pii-multilingual-small/int8/tokenizer.json", "Wismut_nym-pii-multilingual-small/int8/config.json",
       {{"GIVEN_NAME", Person}, {"SURNAME", Person}, {"COMPANY_NAME", Organization}}, {}},
  };
  return list;
}

const Candidate* find_candidate(std::string_view name) {
  for (const auto& c : candidates())
    if (c.name == name) return &c;
  return nullptr;
}

}  // namespace prompt_airlock::ner
