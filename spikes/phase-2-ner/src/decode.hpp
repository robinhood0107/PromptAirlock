#pragma once
// 토큰별 label → PERSON/ORG span. 결과 offset 은 원문 UTF-8 바이트다.
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "model.hpp"
#include "tokenizer.hpp"

namespace prompt_airlock::ner {

enum class EntityType { Person, Organization };  // spec §4 의 부분집합

struct EntitySpan {
  EntityType type;
  ByteSpan bytes;
  bool operator==(const EntitySpan&) const = default;
};

// 모델 label 하나의 해석. type 이 없으면 O 또는 관심 밖 label.
struct LabelInfo {
  std::optional<EntityType> type;
  char prefix = 'O';    // B / I / E / S / O
  std::string subtype;  // 원래 label 이름(SURNAME, GIVEN_NAME 등)
};

// "B-NAME", "I-ORG", "PER-B" 형식을 해석한다. entity_map 은 모델 label → EntityType.
[[nodiscard]] std::vector<LabelInfo> build_label_table(const std::vector<std::string>& id2label,
                                                       const std::map<std::string, EntityType>& entity_map);

struct DecodeOptions {
  // 같은 type 의 span 이 0 바이트 간격으로 맞닿으면 잇는다. 성·이름을 따로 태깅하는 모델이면
  // 공백만 사이에 둔 서로 다른 subtype 의 PERSON 조각도 잇는다.
  bool merge_adjacent = true;
};

[[nodiscard]] std::vector<EntitySpan> decode_entities(std::span<const Token> tokens, const Logits& logits,
                                                      std::span<const LabelInfo> labels,
                                                      std::string_view original, DecodeOptions opts);

// 한국어 조사·호칭 후처리. 받침 호응과 최소 음절 수를 확인한 뒤에만 끝을 잘라낸다.
[[nodiscard]] std::vector<EntitySpan> strip_trailing_particles(std::span<const EntitySpan> spans,
                                                               std::span<const Unit> normalized);

[[nodiscard]] std::string_view to_string(EntityType t);

}  // namespace prompt_airlock::ner
