// 문장 판별기: 문장 나누기 규칙(training/sentence/common.py 와 같음)과, 모델 파일이 없거나 다르면 만들지 않는 것.
// 모델은 저장소 밖에 두므로 확률·판정 일치는 sentence_classifier_measure 와 parity.py 로 잰다(#187).
#include "prompt_airlock/ner/sentence_classifier.hpp"

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
