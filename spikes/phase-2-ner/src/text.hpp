#pragma once
// 원문 → 정규화 텍스트 변환. 정규화 후 각 코드포인트는 원문 바이트 구간을 함께 들고 다닌다.
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "offsets.hpp"

namespace prompt_airlock::ner {

// 정규화된 코드포인트 하나와 그것이 유래한 원문 바이트 구간.
// 합성(NFC)으로 여러 원문 코드포인트가 하나가 되면 src 는 그 전체를 덮는다.
struct Unit {
  char32_t cp{};
  ByteSpan src;
};

enum class TextError { InvalidUtf8, NormalizationFailed };

struct NormPolicy {
  bool nfc = true;               // NFC 합성(NFKC 아님)
  bool strip_zero_width = true;  // U+200B/200C/200D/2060/FEFF 제거
  bool compat = false;           // true 면 NFKC(전각·호환 문자 접기). 비교 측정용
};

// UTF-8 검증 + 디코드. 각 Unit 의 src 는 자기 바이트 구간.
[[nodiscard]] std::expected<std::vector<Unit>, TextError> decode_utf8(std::string_view text);

// 정책에 따라 정규화한다. 실패하면 fail-closed 로 오류를 돌려준다.
[[nodiscard]] std::expected<std::vector<Unit>, TextError> normalize(std::string_view original,
                                                                    NormPolicy policy);

void append_utf8(std::string& out, char32_t cp);
[[nodiscard]] std::string to_utf8(std::span<const Unit> units);

// 원문 바이트 offset → 코드포인트 offset. 코드포인트 경계가 아니면 nullopt 대신 false 반환.
[[nodiscard]] bool is_codepoint_boundary(std::string_view text, Utf8ByteOffset at);
[[nodiscard]] CodepointOffset to_codepoint_offset(std::string_view text, Utf8ByteOffset at);

[[nodiscard]] bool is_zero_width(char32_t cp);
[[nodiscard]] bool is_hangul_syllable(char32_t cp);

}  // namespace prompt_airlock::ner
