// tokenizer.json 을 직접 읽는 WordPiece tokenizer(ADR 0006). 지원하지 않는 구성은 읽을 때 거부한다.
#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "prompt_airlock/core/utf8.hpp"

namespace prompt_airlock::ner {

// 토큰 하나. first_unit..last_unit 는 encode 에 넘긴 units 안의 글자 위치(양 끝 포함)다.
// 앞뒤에 붙는 special token 은 글자가 없어 위치를 쓰지 않는다.
struct Token {
    std::int64_t id;
    std::uint32_t first_unit;
    std::uint32_t last_unit;
    bool special;
};

enum class TokenizerError : std::uint8_t { FileOpen, Parse, Unsupported, MissingToken };

class WordPieceTokenizer {
public:
    // json 은 HF tokenizers 의 tokenizer.json 내용이다. 파싱 예외는 값으로 바꿔 돌려준다.
    [[nodiscard]] static std::expected<WordPieceTokenizer, TokenizerError> parse(std::string_view json);
    [[nodiscard]] static std::expected<WordPieceTokenizer, TokenizerError> load(const std::filesystem::path& file);

    // 결과는 [CLS] ... [SEP] 이다. 사용자 글 안의 "[SEP]" 같은 문자열은 special 로 해석하지 않는다.
    // 토큰 수는 입력 글자 수 + 2 를 넘지 않는다(글자마다 최대 한 토큰, 앞뒤 special 2개).
    [[nodiscard]] std::vector<Token> encode(std::span<const core::DecodedCodepoint> units) const;

    // vocab 문자열. 모르는 id 면 빈 문자열.
    [[nodiscard]] std::string_view piece(std::int64_t id) const noexcept;
    [[nodiscard]] std::int64_t unk_id() const noexcept { return unk_; }

private:
    struct StringHash {
        using is_transparent = void;
        [[nodiscard]] std::size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
    };
    using Vocab = std::unordered_map<std::string, std::int64_t, StringHash, std::equal_to<>>;

    WordPieceTokenizer(Vocab vocab, std::int64_t cls, std::int64_t sep, std::int64_t unk, std::string prefix,
                       std::size_t max_word_chars);

    void word_piece(std::span<const std::pair<char32_t, std::uint32_t>> word, std::vector<Token>& out) const;

    Vocab vocab_;
    std::vector<std::string> pieces_;
    std::int64_t cls_;
    std::int64_t sep_;
    std::int64_t unk_;
    std::string prefix_;
    std::size_t max_word_chars_;
};

}  // namespace prompt_airlock::ner
