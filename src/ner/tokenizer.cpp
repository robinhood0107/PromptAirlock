#include "prompt_airlock/ner/tokenizer.hpp"

#include <utf8proc.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <utility>

namespace prompt_airlock::ner {
namespace {

using json = nlohmann::json;

// vocab id 상한. 이보다 큰 id 는 reverse 표를 부풀리는 입력이므로 거부한다.
constexpr std::int64_t max_vocab_id = 1'000'000;

[[nodiscard]] utf8proc_category_t category(char32_t cp) noexcept {
    return utf8proc_category(static_cast<utf8proc_int32_t>(cp));
}

// Unicode White_Space 속성(HF tokenizers 의 char::is_whitespace 와 같은 집합).
[[nodiscard]] constexpr bool is_white_space(char32_t c) noexcept {
    return (c >= 0x09 && c <= 0x0D) || c == 0x20 || c == 0x85 || c == 0xA0 || c == 0x1680 ||
           (c >= 0x2000 && c <= 0x200A) || c == 0x2028 || c == 0x2029 || c == 0x202F || c == 0x205F ||
           c == 0x3000;
}

[[nodiscard]] bool is_bert_control(char32_t c) noexcept {
    if (c == U'\t' || c == U'\n' || c == U'\r') {
        return false;
    }
    switch (category(c)) {
        case UTF8PROC_CATEGORY_CC:
        case UTF8PROC_CATEGORY_CF:
        case UTF8PROC_CATEGORY_CO:
        case UTF8PROC_CATEGORY_CS:
        case UTF8PROC_CATEGORY_CN:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool is_bert_punct(char32_t c) noexcept {
    if ((c >= 33 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) || (c >= 123 && c <= 126)) {
        return true;
    }
    switch (category(c)) {
        case UTF8PROC_CATEGORY_PC:
        case UTF8PROC_CATEGORY_PD:
        case UTF8PROC_CATEGORY_PS:
        case UTF8PROC_CATEGORY_PE:
        case UTF8PROC_CATEGORY_PI:
        case UTF8PROC_CATEGORY_PF:
        case UTF8PROC_CATEGORY_PO:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] constexpr bool is_cjk_ideograph(char32_t c) noexcept {
    return (c >= 0x4E00 && c <= 0x9FFF) || (c >= 0x3400 && c <= 0x4DBF) || (c >= 0x20000 && c <= 0x2A6DF) ||
           (c >= 0x2A700 && c <= 0x2B73F) || (c >= 0x2B740 && c <= 0x2B81F) || (c >= 0x2B820 && c <= 0x2CEAF) ||
           (c >= 0xF900 && c <= 0xFAFF) || (c >= 0x2F800 && c <= 0x2FA1F);
}

void append_utf8(std::string& out, char32_t c) {
    std::array<utf8proc_uint8_t, 4> buf{};
    const auto n = utf8proc_encode_char(static_cast<utf8proc_int32_t>(c), buf.data());
    out.append(reinterpret_cast<const char*>(buf.data()), static_cast<std::size_t>(n));
}

// 이 구성(BertNormalizer lowercase=false + BertPreTokenizer)만 지원한다. 키가 없거나 다르면 false.
[[nodiscard]] bool is_supported_normalizer(const json& norm, const json& pre) {
    if (!norm.is_object() || !pre.is_object()) {
        return false;
    }
    const auto flag = [&](const char* key, bool want) {
        const auto it = norm.find(key);
        return it != norm.end() && it->is_boolean() && it->get<bool>() == want;
    };
    const auto strip = norm.find("strip_accents");
    const bool strip_ok = strip != norm.end() && (strip->is_null() || (strip->is_boolean() && !strip->get<bool>()));
    return norm.value("type", "") == "BertNormalizer" && flag("clean_text", true) &&
           flag("handle_chinese_chars", true) && flag("lowercase", false) && strip_ok &&
           pre.value("type", "") == "BertPreTokenizer";
}

// TemplateProcessing 의 single 템플릿이 [special] A [special] 인지 확인하고 두 id 를 꺼낸다.
[[nodiscard]] std::expected<std::pair<std::int64_t, std::int64_t>, TokenizerError> wrap_ids(const json& post) {
    if (!post.is_object() || post.value("type", "") != "TemplateProcessing") {
        return std::unexpected(TokenizerError::Unsupported);
    }
    const auto& single = post.at("single");
    if (!single.is_array() || single.size() != 3 || !single[0].contains("SpecialToken") ||
        !single[1].contains("Sequence") || !single[2].contains("SpecialToken")) {
        return std::unexpected(TokenizerError::Unsupported);
    }
    const auto& specials = post.at("special_tokens");
    const auto first = single[0].at("SpecialToken").at("id").get<std::string>();
    const auto last = single[2].at("SpecialToken").at("id").get<std::string>();
    const auto a = specials.at(first).at("ids").at(0).get<std::int64_t>();
    const auto b = specials.at(last).at("ids").at(0).get<std::int64_t>();
    if (a < 0 || b < 0 || a > max_vocab_id || b > max_vocab_id) {
        return std::unexpected(TokenizerError::Unsupported);
    }
    return std::pair{a, b};
}

}  // namespace

WordPieceTokenizer::WordPieceTokenizer(Vocab vocab, std::int64_t cls, std::int64_t sep, std::int64_t unk,
                                       std::string prefix, std::size_t max_word_chars)
    : vocab_(std::move(vocab)), cls_(cls), sep_(sep), unk_(unk), prefix_(std::move(prefix)),
      max_word_chars_(max_word_chars) {
    std::int64_t max_id = -1;
    for (const auto& entry : vocab_) {
        max_id = std::max(max_id, entry.second);
    }
    pieces_.resize(static_cast<std::size_t>(max_id + 1));
    for (const auto& [text, id] : vocab_) {
        pieces_[static_cast<std::size_t>(id)] = text;
    }
}

std::expected<WordPieceTokenizer, TokenizerError> WordPieceTokenizer::parse(std::string_view text) {
    try {
        const auto j = json::parse(text.begin(), text.end());
        const auto& model = j.at("model");
        if (model.value("type", "") != "WordPiece" ||
            !is_supported_normalizer(j.at("normalizer"), j.at("pre_tokenizer"))) {
            return std::unexpected(TokenizerError::Unsupported);
        }
        const auto wrap = wrap_ids(j.at("post_processor"));
        if (!wrap) {
            return std::unexpected(wrap.error());
        }
        Vocab vocab;
        for (const auto& [piece, id] : model.at("vocab").items()) {
            const auto value = id.get<std::int64_t>();
            if (value < 0 || value > max_vocab_id) {
                return std::unexpected(TokenizerError::Unsupported);
            }
            vocab.emplace(piece, value);
        }
        const auto unk = vocab.find(model.at("unk_token").get<std::string>());
        if (unk == vocab.end()) {
            return std::unexpected(TokenizerError::MissingToken);
        }
        return WordPieceTokenizer(std::move(vocab), wrap->first, wrap->second, unk->second,
                                  model.value("continuing_subword_prefix", "##"),
                                  model.value("max_input_chars_per_word", std::size_t{100}));
    } catch (const json::exception&) {
        // 라이브러리 예외는 경계에서 값으로 바꾼다.
        return std::unexpected(TokenizerError::Parse);
    }
}

std::expected<WordPieceTokenizer, TokenizerError> WordPieceTokenizer::load(const std::filesystem::path& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        return std::unexpected(TokenizerError::FileOpen);
    }
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return parse(text);
}

std::string_view WordPieceTokenizer::piece(std::int64_t id) const noexcept {
    return id >= 0 && static_cast<std::size_t>(id) < pieces_.size()
               ? std::string_view{pieces_[static_cast<std::size_t>(id)]}
               : std::string_view{};
}

std::vector<Token> WordPieceTokenizer::encode(std::span<const core::DecodedCodepoint> units) const {
    // BertNormalizer(clean_text, handle_chinese_chars, lowercase=false): 글자와 원래 위치 순번의 쌍으로 만든다.
    std::vector<std::pair<char32_t, std::uint32_t>> norm;
    norm.reserve(units.size());
    for (std::uint32_t i = 0; i < units.size(); ++i) {
        const char32_t c = units[i].value;
        if (c == 0 || c == 0xFFFD || is_bert_control(c)) {
            continue;
        }
        if (is_white_space(c)) {
            norm.emplace_back(U' ', i);
        } else if (is_cjk_ideograph(c)) {
            norm.emplace_back(U' ', i);
            norm.emplace_back(c, i);
            norm.emplace_back(U' ', i);
        } else {
            norm.emplace_back(c, i);
        }
    }

    std::vector<Token> out;
    out.push_back({cls_, 0, 0, true});
    // BertPreTokenizer: 공백으로 나누고(제거) 구두점을 단독 단어로 분리한다.
    std::size_t i = 0;
    while (i < norm.size()) {
        if (is_white_space(norm[i].first)) {
            ++i;
            continue;
        }
        std::size_t j = i + 1;
        if (!is_bert_punct(norm[i].first)) {
            while (j < norm.size() && !is_white_space(norm[j].first) && !is_bert_punct(norm[j].first)) {
                ++j;
            }
        }
        word_piece(std::span(norm).subspan(i, j - i), out);
        i = j;
    }
    out.push_back({sep_, 0, 0, true});
    return out;
}

void WordPieceTokenizer::word_piece(std::span<const std::pair<char32_t, std::uint32_t>> word,
                                    std::vector<Token>& out) const {
    const auto whole_first = word.front().second;
    const auto whole_last = word.back().second;
    if (word.size() > max_word_chars_) {
        out.push_back({unk_, whole_first, whole_last, false});
        return;
    }
    std::vector<std::string> chars;  // 글자별 UTF-8
    chars.reserve(word.size());
    for (const auto& [c, index] : word) {
        std::string s;
        append_utf8(s, c);
        chars.push_back(std::move(s));
    }
    std::vector<Token> pieces;
    std::size_t start = 0;
    while (start < word.size()) {
        std::size_t end = word.size();
        bool found = false;
        while (start < end) {
            std::string candidate = start > 0 ? prefix_ : std::string{};
            for (std::size_t k = start; k < end; ++k) {
                candidate += chars[k];
            }
            if (const auto it = vocab_.find(candidate); it != vocab_.end()) {
                pieces.push_back({it->second, word[start].second, word[end - 1].second, false});
                found = true;
                break;
            }
            --end;
        }
        if (!found) {
            // 단어 전체를 UNK 하나로 바꾼다.
            out.push_back({unk_, whole_first, whole_last, false});
            return;
        }
        start = end;
    }
    out.insert(out.end(), pieces.begin(), pieces.end());
}

}  // namespace prompt_airlock::ner
