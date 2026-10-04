#pragma once
// 측정 후보 목록. 모델 파일은 models/phase-2 에 두며 저장소에 추적하지 않는다.
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "decode.hpp"

namespace prompt_airlock::ner {

struct Candidate {
  std::string name;
  std::string repo;
  std::string commit;
  std::filesystem::path onnx;       // model root 기준 상대 경로
  std::filesystem::path tokenizer;  // tokenizer.json
  std::filesystem::path config;     // id2label 이 들어 있는 config.json
  std::map<std::string, EntityType> entity_map;
  DecodeOptions decode;
  std::size_t max_tokens = 512;  // spec §37 NER max input. 초과 시 자르지 않고 거부.
};

[[nodiscard]] const std::vector<Candidate>& candidates();
[[nodiscard]] const Candidate* find_candidate(std::string_view name);

}  // namespace prompt_airlock::ner
