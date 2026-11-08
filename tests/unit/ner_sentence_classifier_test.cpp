// 문장 판별기: 문장 나누기 규칙(training/sentence/common.py 와 같음)과, 모델 파일이 없거나 다르면 만들지 않는 것.
// 모델은 저장소 밖에 두므로 확률·판정 일치는 sentence_classifier_measure 와 parity.py 로 잰다(#187).
#include "prompt_airlock/ner/sentence_classifier.hpp"
#include "prompt_airlock/ner/tokenizer.hpp"
#include "prompt_airlock/core/utf8.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace pn = prompt_airlock::ner;
namespace fs = std::filesystem;

namespace {

std::vector<std::string> split(std::string_view text) {
    std::vector<std::string> out;
    for (const auto s : pn::split_sentences(text)) {
        out.emplace_back(s);
    }
    return out;
}

TEST(SentenceSplit, MatchesPythonRule) {
    EXPECT_EQ(split("가.\n\n나"), (std::vector<std::string>{"가.", "\n나"}));
    EXPECT_EQ(split("회의는 3시. 김 과장은 늦어요."), (std::vector<std::string>{"회의는 3시.", " 김 과장은 늦어요."}));
    EXPECT_EQ(split("a.b c"), (std::vector<std::string>{"a.b c"}));
    EXPECT_TRUE(split("").empty());
    EXPECT_TRUE(split(" \n ").empty());
    EXPECT_EQ(split("정말요?! 네"), (std::vector<std::string>{"정말요?!", " 네"}));
}

TEST(SentenceClassifier, MissingOrChangedFilesAreUnavailable) {
    const auto dir = fs::temp_directory_path() / "pa_sentence_classifier_missing";
    fs::remove_all(dir);
    fs::create_directories(dir);
    auto made = pn::SentenceClassifier::make(dir);
    ASSERT_FALSE(made);
    EXPECT_EQ(made.error(), pn::SentenceError::Unavailable);
    // 해시가 다른 설정 파일은 모델을 읽기 전에 거절한다.
    std::ofstream(dir / "classifier.json") << R"({"version":1})";
    made = pn::SentenceClassifier::make(dir);
    ASSERT_FALSE(made);
    EXPECT_EQ(made.error(), pn::SentenceError::Unavailable);
    fs::remove_all(dir);
}

}  // namespace
#ifdef PA_TEST_SENTENCE_MODEL_DIR
TEST(SentenceClassifier, PinnedModelProcessesEveryWindowOfLongSentences) {
    const auto made = pn::SentenceClassifier::make(PA_TEST_SENTENCE_MODEL_DIR);
    ASSERT_TRUE(made);
    const std::string tail = "김민준의 업무 계정 비밀번호는 Summer2026! 입니다";
    const auto control = (*made)->classify(tail, true);
    ASSERT_TRUE(control && *control);
    EXPECT_EQ((*control)->category, "Credential");
    std::string text;
    for (int i = 0; i < 400; ++i) text += "회의 안내 ";
    text += tail;
    auto tokenizer = pn::WordPieceTokenizer::load(fs::path(PA_TEST_SENTENCE_MODEL_DIR) / "tokenizer.json");
    ASSERT_TRUE(tokenizer);
    std::size_t expected_tokens = 0;
    const auto sentences = pn::split_sentences(text);
    for (const auto sentence : sentences) {
        const auto units = prompt_airlock::core::decode_utf8(sentence);
        ASSERT_TRUE(units);
        expected_tokens += tokenizer->encode(*units).size() - 2;
    }
    pn::SentenceScanStatistics statistics;
    const auto hit = (*made)->classify(text, true, {}, &statistics);
    ASSERT_TRUE(hit);
    EXPECT_GT(expected_tokens, 256U);
    EXPECT_EQ(statistics.tokens, expected_tokens);
    EXPECT_EQ(statistics.checked_tokens, expected_tokens);
    EXPECT_GT(statistics.windows, sentences.size());
    std::stop_source stop;
    stop.request_stop();
    const auto cancelled = (*made)->classify(text, true, stop.get_token(), &statistics);
    ASSERT_FALSE(cancelled);
    EXPECT_EQ(cancelled.error(), pn::SentenceError::Timeout);
    EXPECT_EQ(statistics.windows, 0U);
}
#endif
