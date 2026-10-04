#pragma once
// tokenizer.json 을 읽는 native C++ tokenizer. 지원하지 않는 구성은 로드 단계에서 거부한다.
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "text.hpp"

namespace prompt_airlock::ner {

struct Token {
  std::int64_t id{};
  ByteSpan src;  // 원문 바이트 구간. special token 은 빈 구간.
  bool special = false;
};

enum class TokError { FileOpen, Parse, Unsupported, MissingToken };

class Tokenizer {
 public:
  virtual ~Tokenizer() = default;
  // 입력은 normalize() 결과. 결과는 앞뒤 special token 을 포함한다.
  // 사용자 텍스트 안의 special token 문자열([SEP], <bos> 등)은 special 로 해석하지 않는다.
  [[nodiscard]] virtual std::vector<Token> encode(std::span<const Unit> units) const = 0;
  [[nodiscard]] virtual std::string_view kind() const = 0;
  // vocab 문자열. 모르는 id 면 빈 문자열.
  [[nodiscard]] virtual std::string_view piece(std::int64_t id) const = 0;
  [[nodiscard]] virtual bool is_byte_fallback(std::int64_t id) const = 0;
  [[nodiscard]] virtual std::int64_t unk_id() const = 0;
};

[[nodiscard]] std::expected<std::unique_ptr<const Tokenizer>, TokError> load_tokenizer(
    const std::filesystem::path& tokenizer_json);

[[nodiscard]] std::string_view to_string(TokError e);

}  // namespace prompt_airlock::ner
