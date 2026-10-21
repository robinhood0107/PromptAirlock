// WordPiece tokenizer: 개발용 oracle(transformers.js 4.3.0)이 만든 id 와 같은지, 지원하지 않는 구성을 거부하는지.
#include "prompt_airlock/ner/tokenizer.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "prompt_airlock/detect/view.hpp"

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pn = prompt_airlock::ner;

namespace {

const std::filesystem::path model_dir = PA_NER_MODEL_DIR;
const std::filesystem::path fixture_dir = PA_NER_FIXTURE_DIR;

const pn::WordPieceTokenizer& tokenizer() {
    static const auto loaded = pn::WordPieceTokenizer::load(model_dir / "tokenizer.json");
    return *loaded;
}

std::vector<std::int64_t> ids_of(std::string_view text) {
    const auto units = pc::decode_utf8(text);
    std::vector<std::int64_t> ids;
    for (const auto& token : tokenizer().encode(*units)) {
        ids.push_back(token.id);
    }
    return ids;
}

// oracle 한 파일의 모든 줄을 비교하고 일치한 수를 돌려준다.
std::size_t compare_with_oracle(const std::string& name, std::size_t& total) {
    std::ifstream in(fixture_dir / "oracle" / name, std::ios::binary);
    EXPECT_TRUE(in) << name;
    std::size_t exact = 0;
    std::string line;
    while (std::getline(in, line)) {
        const auto j = nlohmann::json::parse(line);
        ++total;
        if (ids_of(j.at("norm_text").get<std::string>()) == j.at("ids").get<std::vector<std::int64_t>>()) {
            ++exact;
        } else {
            ADD_FAILURE() << name << " mismatch: " << j.at("id").get<std::string>();
        }
    }
    return exact;
}

constexpr const char* supported_config = R"({
  "normalizer":{"type":"BertNormalizer","clean_text":true,"handle_chinese_chars":true,"strip_accents":null,"lowercase":false},
  "pre_tokenizer":{"type":"BertPreTokenizer"},
  "post_processor":{"type":"TemplateProcessing","single":[{"SpecialToken":{"id":"[CLS]","type_id":0}},
    {"Sequence":{"id":"A","type_id":0}},{"SpecialToken":{"id":"[SEP]","type_id":0}}],
    "special_tokens":{"[CLS]":{"id":"[CLS]","ids":[2],"tokens":["[CLS]"]},"[SEP]":{"id":"[SEP]","ids":[3],"tokens":["[SEP]"]}}},
  "model":{"type":"WordPiece","unk_token":"[UNK]","vocab":{"[UNK]":1,"[CLS]":2,"[SEP]":3,"a":4,"##b":5}}})";

std::string replaced(std::string text, std::string_view from, std::string_view to) {
    const auto at = text.find(from);
    EXPECT_NE(at, std::string::npos);
    return text.replace(at, from.size(), to);
}

}  // namespace

TEST(NerTokenizer, MatchesOracleIds) {
    std::size_t total = 0;
    const auto exact = compare_with_oracle("atonlee-raw.jsonl", total) + compare_with_oracle("atonlee-nfc.jsonl", total);
    RecordProperty("exact_match", std::to_string(exact) + "/" + std::to_string(total));
    EXPECT_EQ(total, 120u);
    EXPECT_EQ(exact, total);
}

TEST(NerTokenizer, SpecialTokenTextInUserInputIsNotSpecial) {
    const auto units = pc::decode_utf8("김민수 [SEP] [CLS] 이영희");
    const auto tokens = tokenizer().encode(*units);
    ASSERT_GT(tokens.size(), 2u);
    EXPECT_TRUE(tokens.front().special);
    EXPECT_TRUE(tokens.back().special);
    for (std::size_t i = 1; i + 1 < tokens.size(); ++i) {
        EXPECT_FALSE(tokens[i].special);
        EXPECT_NE(tokens[i].id, tokens.front().id);
        EXPECT_NE(tokens[i].id, tokens.back().id);
    }
}

TEST(NerTokenizer, TokenUnitRangesPointAtTheirOwnCharacters) {
    const std::string text = "김민수가 왔다";
    const auto units = pc::decode_utf8(text);
    const auto tokens = tokenizer().encode(*units);
    std::uint32_t previous_last = 0;
    bool first = true;
    for (const auto& token : tokens) {
        if (token.special) {
            continue;
        }
        EXPECT_LE(token.first_unit, token.last_unit);
        EXPECT_LT(token.last_unit, units->size());
        if (!first) {
            EXPECT_GT(token.first_unit, previous_last);
        }
        previous_last = token.last_unit;
        first = false;
    }
}

// 역검증: 모든 fixture 에서 토큰이 가리키는 보기 글자가 그 토큰의 vocab 문자열과 같다.
TEST(NerTokenizer, TokenUnitRangesReproduceTheirVocabPieces) {
    std::ifstream in(fixture_dir / "ner.jsonl", std::ios::binary);
    std::string line;
    std::size_t checked = 0;
    std::size_t errors = 0;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        const auto text = nlohmann::json::parse(line).at("text").get<std::string>();
        const auto view = pd::make_view(text);
        ASSERT_TRUE(view);
        for (const auto& token : tokenizer().encode(view->units)) {
            if (token.special || token.id == tokenizer().unk_id()) {
                continue;
            }
            std::u32string chars;
            for (auto i = token.first_unit; i <= token.last_unit; ++i) {
                chars.push_back(view->units[i].value);
            }
            auto want = std::string(tokenizer().piece(token.id));
            if (want.starts_with("##")) {
                want.erase(0, 2);
            }
            std::u32string got;
            // 임시 expected 의 값을 직접 돌면 gcc-14 에서 매달린다(범위 for 의 임시 수명 연장은 C++23 부터).
            const auto decoded = pc::decode_utf8(want);
            ASSERT_TRUE(decoded);
            for (const auto& unit : *decoded) {
                got.push_back(unit.value);
            }
            ++checked;
            errors += got == chars ? 0 : 1;
        }
    }
    RecordProperty("tokens_checked", std::to_string(checked));
    EXPECT_GT(checked, 0u);
    EXPECT_EQ(errors, 0u);
}

TEST(NerTokenizer, EmptyInputGivesOnlySpecialTokens) {
    const std::vector<pc::DecodedCodepoint> none;
    EXPECT_EQ(tokenizer().encode(none).size(), 2u);
}

TEST(NerTokenizer, UnknownWordBecomesOneUnkToken) {
    const auto tok = pn::WordPieceTokenizer::parse(supported_config);
    ASSERT_TRUE(tok);
    const auto units = pc::decode_utf8("ab zz a");
    const auto tokens = tok->encode(*units);
    ASSERT_EQ(tokens.size(), 6u);  // [CLS] a ##b [UNK] a [SEP]
    EXPECT_EQ(tokens[1].id, 4);
    EXPECT_EQ(tokens[2].id, 5);
    EXPECT_EQ(tokens[3].id, tok->unk_id());
    EXPECT_EQ(tokens[3].first_unit, 3u);
    EXPECT_EQ(tokens[3].last_unit, 4u);
    EXPECT_EQ(tok->piece(5), "##b");
    EXPECT_TRUE(tok->piece(99).empty());
}

TEST(NerTokenizer, RejectsUnsupportedConfigurations) {
    EXPECT_TRUE(pn::WordPieceTokenizer::parse(supported_config));
    for (const auto& [from, to] : {std::pair<std::string_view, std::string_view>{"\"lowercase\":false", "\"lowercase\":true"},
                                   {"\"BertPreTokenizer\"", "\"Whitespace\""},
                                   {"\"WordPiece\"", "\"BPE\""},
                                   {"\"TemplateProcessing\"", "\"ByteLevel\""},
                                   {"\"strip_accents\":null", "\"strip_accents\":true"},
                                   {"\"ids\":[2]", "\"ids\":[-2]"},
                                   {"\"[UNK]\":1,", "\"[UNK]\":99999999999,"}}) {
        const auto tok = pn::WordPieceTokenizer::parse(replaced(supported_config, from, to));
        ASSERT_FALSE(tok) << from;
        EXPECT_EQ(tok.error(), pn::TokenizerError::Unsupported) << from;
    }
}

TEST(NerTokenizer, MissingUnkTokenIsRejected) {
    const auto tok = pn::WordPieceTokenizer::parse(replaced(supported_config, "\"unk_token\":\"[UNK]\"", "\"unk_token\":\"[NONE]\""));
    ASSERT_FALSE(tok);
    EXPECT_EQ(tok.error(), pn::TokenizerError::MissingToken);
}

TEST(NerTokenizer, BrokenJsonIsAValueNotAnException) {
    for (const std::string_view text : {"", "{", "[]", "{}", "null", R"({"model":1})", "\xff\xfe"}) {
        const auto tok = pn::WordPieceTokenizer::parse(text);
        ASSERT_FALSE(tok) << text;
        EXPECT_EQ(tok.error(), pn::TokenizerError::Parse) << text;
    }
    EXPECT_EQ(pn::WordPieceTokenizer::load(model_dir / "no-such-file.json").error(), pn::TokenizerError::FileOpen);
}
