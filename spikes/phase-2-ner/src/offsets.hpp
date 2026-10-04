#pragma once
// spec §22: byte / codepoint / token offset 을 같은 size_t 의미로 섞지 않는다.
#include <compare>
#include <cstddef>

namespace prompt_airlock::ner {

// 원문 UTF-8 바이트 위치. canonical offset 후보.
struct Utf8ByteOffset {
  std::size_t value{};
  auto operator<=>(const Utf8ByteOffset&) const = default;
};

// 원문 코드포인트 위치. 표시·디버깅용 파생값이다.
struct CodepointOffset {
  std::size_t value{};
  auto operator<=>(const CodepointOffset&) const = default;
};

// 모델 입력 시퀀스 안의 토큰 위치.
struct TokenIndex {
  std::size_t value{};
  auto operator<=>(const TokenIndex&) const = default;
};

// 원문 UTF-8 바이트 반열린 구간 [begin, end).
struct ByteSpan {
  Utf8ByteOffset begin;
  Utf8ByteOffset end;
  [[nodiscard]] bool empty() const { return begin.value >= end.value; }
  [[nodiscard]] std::size_t size() const { return empty() ? 0 : end.value - begin.value; }
  bool operator==(const ByteSpan&) const = default;
};

}  // namespace prompt_airlock::ner
