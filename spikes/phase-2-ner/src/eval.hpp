#pragma once
// fixture 채점과 offset 검증. bench 와 테스트가 같은 규칙을 쓴다.
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fixtures.hpp"
#include "pipeline.hpp"

namespace prompt_airlock::ner {

struct OffsetReport {
  std::size_t tokens_checked = 0;
  std::size_t token_errors = 0;   // 토큰 원문 구간이 vocab 문자열과 다르거나 경계가 깨짐
  std::size_t entity_errors = 0;  // entity 구간이 범위 밖·코드포인트 중간·빈 구간·앞뒤 공백
  std::vector<std::string> details;
};

// 각 토큰의 원문 바이트 구간을 다시 정규화했을 때 토큰 문자열과 같아야 한다.
[[nodiscard]] OffsetReport verify_offsets(std::string_view original, const Analysis& a, const Tokenizer& tok,
                                          NormPolicy policy);

struct TypeCounts {
  std::size_t tp = 0, fp = 0, fn = 0;
};

struct Score {
  TypeCounts person, org;
  std::size_t particle_errors = 0;  // 시작은 같고 끝이 한글(조사·호칭)을 더 포함
  std::size_t other_boundary = 0;   // 같은 type 으로 겹치지만 위 경우가 아님
  std::vector<std::string> misses;  // 사람이 읽을 요약
};

[[nodiscard]] Score score(const Fixture& f, std::span<const EntitySpan> preds);

}  // namespace prompt_airlock::ner
