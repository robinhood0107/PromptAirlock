// 실제 후보 모델로 offset 정확성과 fail-closed 동작을 확인한다. 품질 수치는 ner_bench 가 기록한다.
#include <gtest/gtest.h>

#include <filesystem>
#include <optional>

#include "eval.hpp"

using namespace prompt_airlock::ner;

namespace {

const std::filesystem::path kModels = PA_MODEL_DIR;

class PipelineTest : public ::testing::TestWithParam<std::string> {
 protected:
  Ort::Env env_{ORT_LOGGING_LEVEL_WARNING, "pa-phase2-test"};  // 테스트마다 생성, 세션보다 오래 산다
  std::optional<Pipeline> load() {
    const auto* c = find_candidate(GetParam());
    if (!c || !std::filesystem::exists(kModels / c->onnx)) return std::nullopt;
    auto p = Pipeline::load(env_, *c, kModels);
    EXPECT_TRUE(p) << (p ? "" : p.error());
    if (!p) return std::nullopt;
    return std::move(*p);
  }
};

}  // namespace

TEST_P(PipelineTest, AllFixtureOffsetsMapBackToOriginalBytes) {
  auto p = load();
  if (!p) GTEST_SKIP() << "model files absent";
  auto fx = load_fixtures(std::filesystem::path(PA_FIXTURE_DIR) / "ner.jsonl");
  ASSERT_TRUE(fx);
  std::size_t checked = 0;
  for (const auto& f : *fx) {
    auto a = p->analyze(f.text);
    ASSERT_TRUE(a) << f.id;
    const auto r = verify_offsets(f.text, *a, p->tokenizer(), {});
    checked += r.tokens_checked;
    EXPECT_EQ(r.token_errors, 0u) << f.id << (r.details.empty() ? "" : " " + r.details.front());
    EXPECT_EQ(r.entity_errors, 0u) << f.id;
  }
  RecordProperty("tokens_checked", std::to_string(checked));
  EXPECT_GT(checked, 0u);
}

TEST_P(PipelineTest, InvalidUtf8FailsClosed) {
  auto p = load();
  if (!p) GTEST_SKIP() << "model files absent";
  auto a = p->analyze("김민수\xFF");
  ASSERT_FALSE(a);
  EXPECT_EQ(a.error(), PipelineError::Text);
}

TEST_P(PipelineTest, OverLimitInputIsRejectedNotTruncated) {
  auto p = load();
  if (!p) GTEST_SKIP() << "model files absent";
  std::string big;
  for (int i = 0; i < 400; ++i) big += "김민수는 누리별테크에 다닌다. ";
  auto a = p->analyze(big);
  ASSERT_FALSE(a);
  EXPECT_EQ(a.error(), PipelineError::InputTooLong);
}

INSTANTIATE_TEST_SUITE_P(Candidates, PipelineTest,
                         ::testing::Values("koelectra-small-pii", "koelectra-small-pii-int8", "veil-ko-lite-int8",
                                           "nym-mmbert-small-int8"),
                         [](const auto& info) {
                           std::string n = info.param;
                           for (auto& ch : n)
                             if (ch == '-') ch = '_';
                           return n;
                         });
