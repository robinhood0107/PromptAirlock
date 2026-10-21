// 큰 합성 NER 셋(개발용 ner-large, 1차·2차 판정용 ner-heldout·ner-heldout2, 최종 판정용 ner-final)의 무결성.
// 측정이 이 셋을 믿고 쓰므로 개수, 정답 위치, 셋끼리 문장이 겹치지 않는 것을 고정한다.
// 셋은 gen-large.mjs 가 만든다. 생성기를 바꾸면 셋을 다시 만들어 함께 커밋한다.
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <string>

#include "prompt_airlock/core/utf8.hpp"

namespace pc = prompt_airlock::core;

namespace {

// 셋 하나를 읽어 확인하고 문장 집합을 돌려준다.
std::set<std::string> check_set(const char* file) {
    std::ifstream in(std::filesystem::path(PA_NER_FIXTURE_DIR) / file, std::ios::binary);
    EXPECT_TRUE(in) << file;
    std::map<std::string, int> entities;
    std::map<std::string, int> sentences;
    std::set<std::string> ids;
    std::set<std::string> texts;
    std::string line;
    while (std::getline(in, line)) {
        const auto j = nlohmann::json::parse(line);
        const auto id = j.at("id").get<std::string>();
        const auto text = j.at("text").get<std::string>();
        EXPECT_TRUE(ids.insert(id).second) << id;
        EXPECT_TRUE(texts.insert(text).second) << id;  // 같은 문장이 두 번 들어가면 수치가 부풀려진다
        EXPECT_TRUE(pc::decode_utf8(text)) << id;
        ++sentences[j.at("category").get<std::string>()];
        for (const auto& e : j.at("entities")) {
            const auto begin = e.at("start_byte").get<std::size_t>();
            const auto end = e.at("end_byte").get<std::size_t>();
            EXPECT_LT(begin, end) << id;
            if (end > text.size()) {
                ADD_FAILURE() << id;
                continue;
            }
            EXPECT_EQ(text.substr(begin, end - begin), e.at("text").get<std::string>()) << id;
            ++entities[e.at("type").get<std::string>()];
        }
    }
    EXPECT_EQ(sentences["person"], 300);
    EXPECT_EQ(sentences["organization"], 300);
    EXPECT_EQ(sentences["negative"], 300);
    EXPECT_EQ(entities["PERSON"], 300);
    EXPECT_EQ(entities["ORG"], 300);
    return texts;
}

}  // namespace

TEST(NerFixture, AllSetsHaveTheAgreedCountsExactGoldOffsetsAndNoSharedSentence) {
    const auto dev = check_set("ner-large.jsonl");
    const auto heldout = check_set("ner-heldout.jsonl");
    const auto heldout2 = check_set("ner-heldout2.jsonl");
    const auto final_set = check_set("ner-final.jsonl");
    for (const auto& text : heldout) {
        EXPECT_FALSE(dev.contains(text)) << "1차 판정용 문장이 개발용에도 있다";
    }
    for (const auto& text : heldout2) {
        EXPECT_FALSE(dev.contains(text) || heldout.contains(text)) << "2차 판정용 문장이 다른 셋에도 있다";
    }
    for (const auto& text : final_set) {
        EXPECT_FALSE(dev.contains(text) || heldout.contains(text) || heldout2.contains(text)) << "최종 판정용 문장이 다른 셋에도 있다";
    }
}
