// 큰 합성 NER 셋(tests/fixtures/ner/ner-large.jsonl)의 무결성. 측정이 이 셋을 믿고 쓰므로 개수와 정답 위치를 고정한다.
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

TEST(NerFixture, LargeSetHasTheAgreedCountsAndExactGoldOffsets) {
    std::ifstream in(std::filesystem::path(PA_NER_FIXTURE_DIR) / "ner-large.jsonl", std::ios::binary);
    ASSERT_TRUE(in);
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
        ASSERT_TRUE(pc::decode_utf8(text)) << id;
        ++sentences[j.at("category").get<std::string>()];
        for (const auto& e : j.at("entities")) {
            const auto begin = e.at("start_byte").get<std::size_t>();
            const auto end = e.at("end_byte").get<std::size_t>();
            ASSERT_LT(begin, end) << id;
            ASSERT_LE(end, text.size()) << id;
            EXPECT_EQ(text.substr(begin, end - begin), e.at("text").get<std::string>()) << id;
            ++entities[e.at("type").get<std::string>()];
        }
    }
    EXPECT_EQ(sentences["person"], 300);
    EXPECT_EQ(sentences["organization"], 300);
    EXPECT_EQ(sentences["negative"], 300);
    EXPECT_EQ(entities["PERSON"], 300);
    EXPECT_EQ(entities["ORG"], 300);
}
