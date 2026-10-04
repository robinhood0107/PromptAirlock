// native tokenizer 를 oracle(transformers.js 4.3.0, 개발 전용)이 만든 id 와 비교한다.
// oracle 파일은 fixtures/oracle/ 에 커밋되며 모델 파일이 없으면 건너뛴다.
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <map>

#include <nlohmann/json.hpp>

#include "fixtures.hpp"
#include "tokenizer.hpp"

using namespace prompt_airlock::ner;

namespace {

const std::filesystem::path kModels = PA_MODEL_DIR;
const std::filesystem::path kFixtures = PA_FIXTURE_DIR;

struct OracleCase {
  std::string tokenizer;  // model root 기준
  std::string oracle;     // fixtures/oracle 파일 이름
};

const OracleCase kCases[] = {
    {"atonlee_koelectra-ko-pii-ner/tokenizer.json", "atonlee"},
    {"1T_veil-pii-ko-lite/tokenizer.json", "veil"},
    {"Wismut_nym-pii-multilingual-small/int8/tokenizer.json", "nym"},
};

void compare_with_oracle(const OracleCase& c, const std::string& mode) {
  const auto tok_path = kModels / c.tokenizer;
  if (!std::filesystem::exists(tok_path)) GTEST_SKIP() << "model files absent: " << tok_path;
  const auto oracle_path = kFixtures / "oracle" / (c.oracle + "-" + mode + ".jsonl");
  std::ifstream in(oracle_path, std::ios::binary);
  ASSERT_TRUE(in) << oracle_path;
  auto tok = load_tokenizer(tok_path);
  ASSERT_TRUE(tok) << to_string(tok.error());
  auto fx = load_fixtures(kFixtures / "ner.jsonl");
  ASSERT_TRUE(fx);
  std::map<std::string, std::string> text_by_id;
  for (const auto& f : *fx) text_by_id[f.id] = f.text;

  const NormPolicy policy = mode == "raw" ? NormPolicy{false, false} : NormPolicy{};
  std::size_t total = 0, exact = 0;
  std::string line;
  while (std::getline(in, line)) {
    const auto j = nlohmann::json::parse(line);
    const auto id = j.at("id").get<std::string>();
    auto norm = normalize(text_by_id.at(id), policy);
    ASSERT_TRUE(norm) << id;
    // oracle 이 받은 입력과 같은 문자열을 토큰화하는지 먼저 확인
    ASSERT_EQ(to_utf8(*norm), j.at("norm_text").get<std::string>()) << id;
    std::vector<std::int64_t> ids;
    for (const auto& t : (*tok)->encode(*norm)) ids.push_back(t.id);
    ++total;
    if (ids == j.at("ids").get<std::vector<std::int64_t>>()) ++exact;
    else ADD_FAILURE() << c.oracle << "/" << mode << " mismatch: " << id;
  }
  ::testing::Test::RecordProperty("exact_match", std::to_string(exact) + "/" + std::to_string(total));
  EXPECT_EQ(total, fx->size());
  EXPECT_EQ(exact, total);
}

}  // namespace

TEST(TokenizerOracle, KoElectraWordPieceNfc) { compare_with_oracle(kCases[0], "nfc"); }
TEST(TokenizerOracle, KoElectraWordPieceRaw) { compare_with_oracle(kCases[0], "raw"); }
TEST(TokenizerOracle, VeilWordPieceNfc) { compare_with_oracle(kCases[1], "nfc"); }
TEST(TokenizerOracle, VeilWordPieceRaw) { compare_with_oracle(kCases[1], "raw"); }
TEST(TokenizerOracle, NymMetaspaceBpeNfc) { compare_with_oracle(kCases[2], "nfc"); }
TEST(TokenizerOracle, NymMetaspaceBpeRaw) { compare_with_oracle(kCases[2], "raw"); }

TEST(TokenizerSafety, SpecialTokenTextInUserInputIsNotSpecial) {
  const auto path = kModels / kCases[0].tokenizer;
  if (!std::filesystem::exists(path)) GTEST_SKIP();
  auto tok = load_tokenizer(path);
  ASSERT_TRUE(tok);
  auto n = normalize("김민수 [SEP] [CLS] 이영희", {});
  ASSERT_TRUE(n);
  const auto toks = (*tok)->encode(*n);
  for (std::size_t i = 1; i + 1 < toks.size(); ++i) {
    EXPECT_FALSE(toks[i].special);
    EXPECT_NE(toks[i].id, 2);  // [CLS]
    EXPECT_NE(toks[i].id, 3);  // [SEP]
  }
}

TEST(TokenizerSafety, UnsupportedConfigurationIsRejected) {
  const auto tmp = std::filesystem::temp_directory_path() / "pa_phase2_bad_tokenizer.json";
  {
    std::ofstream o(tmp, std::ios::binary);
    o << R"({"normalizer":{"type":"BertNormalizer","clean_text":true,"handle_chinese_chars":true,
      "strip_accents":null,"lowercase":true},"pre_tokenizer":{"type":"BertPreTokenizer"},
      "post_processor":{"type":"TemplateProcessing","single":[{"SpecialToken":{"id":"[CLS]","type_id":0}},
      {"Sequence":{"id":"A","type_id":0}},{"SpecialToken":{"id":"[SEP]","type_id":0}}],
      "special_tokens":{"[CLS]":{"id":"[CLS]","ids":[2],"tokens":["[CLS]"]},"[SEP]":{"id":"[SEP]","ids":[3],"tokens":["[SEP]"]}}},
      "added_tokens":[],"model":{"type":"WordPiece","unk_token":"[UNK]","vocab":{"[UNK]":1}}})";
  }
  auto tok = load_tokenizer(tmp);
  ASSERT_FALSE(tok);
  EXPECT_EQ(tok.error(), TokError::Unsupported);  // lowercase=true 는 지원 안 함 → 거부
  std::filesystem::remove(tmp);
  EXPECT_EQ(load_tokenizer(tmp).error(), TokError::FileOpen);
}
