// NER 엔진: 실제 모델로 합성 문장을 탐지하고, 결과 위치가 원문 byte 와 맞는지 역으로 확인한다.
#include "prompt_airlock/ner/engine.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>
#include <vector>

#include "prompt_airlock/core/utf8.hpp"

namespace fs = std::filesystem;
namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pn = prompt_airlock::ner;

namespace {

const fs::path model_dir = PA_NER_MODEL_DIR;
const fs::path fixture_dir = PA_NER_FIXTURE_DIR;

pn::NerEngine& engine() {
    static auto made = pn::NerEngine::make(model_dir);
    return *made;
}

struct Found {
    pc::EntityType type;
    std::string text;
    bool operator==(const Found&) const = default;
};

std::expected<std::vector<pc::EntitySpan>, pn::NerError> detect_once(const std::string& text) {
    const auto view = pd::make_view(text);
    EXPECT_TRUE(view);
    return engine().detect(text, pc::SegmentIndex{0}, *view, {0, static_cast<std::uint32_t>(view->units.size())});
}

std::vector<Found> found(const std::string& text) {
    const auto spans = detect_once(text);
    EXPECT_TRUE(spans);
    std::vector<Found> out;
    for (const auto& e : *spans) {
        out.push_back({e.type(), text.substr(e.span().begin().value(), e.span().size())});
    }
    return out;
}

Found person(std::string text) { return {pc::EntityType::Person, std::move(text)}; }
Found organization(std::string text) { return {pc::EntityType::Organization, std::move(text)}; }

struct Fixture {
    std::string id;
    std::string text;
    std::vector<Found> gold;
};

std::vector<Fixture> fixtures() {
    std::ifstream in(fixture_dir / "ner.jsonl", std::ios::binary);
    std::vector<Fixture> out;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        const auto j = nlohmann::json::parse(line);
        Fixture f{j.at("id").get<std::string>(), j.at("text").get<std::string>(), {}};
        for (const auto& e : j.at("entities")) {
            const auto type = e.at("type").get<std::string>() == "PERSON" ? pc::EntityType::Person
                                                                         : pc::EntityType::Organization;
            f.gold.push_back({type, e.at("text").get<std::string>()});
        }
        out.push_back(std::move(f));
    }
    return out;
}

}  // namespace

TEST(NerEngine, FindsPersonsAndOrganizationsWithoutParticles) {
    EXPECT_EQ(found("김민수가 내일 회의에 참석합니다."), (std::vector{person("김민수")}));
    EXPECT_EQ(found("어제 박서준을 만났다."), (std::vector{person("박서준")}));
    EXPECT_EQ(found("김민수는 누리별테크에 다닌다."), (std::vector{person("김민수"), organization("누리별테크")}));
    EXPECT_EQ(found("다온바이오와 새온전자가 공동 연구를 발표했다."),
              (std::vector{organization("다온바이오"), organization("새온전자")}));
}

TEST(NerEngine, SentenceWithoutNamesFindsNothing) {
    EXPECT_TRUE(found("오늘은 날씨가 맑고 바람이 시원합니다.").empty());
}

// 띄어 쓰지 않은 두 이름은 맞닿은 같은 종류라 하나로 묶인다(결합 규칙 그대로). 가명화 범위가 넓어질 뿐 빠지지는 않는다.
TEST(NerEngine, TwoNamesWrittenTogetherBecomeOneSpan) {
    EXPECT_EQ(found("김민수이영희가 회의에 왔다."), (std::vector<Found>{person("김민수이영희")}));
}

TEST(NerEngine, EveryResultIsMarkedNerAndValidAgainstTheText) {
    const std::string text = "푸른바다물산 대표 박서준은 하람대학교를 졸업했다.";
    const auto spans = detect_once(text);
    ASSERT_TRUE(spans);
    ASSERT_FALSE(spans->empty());
    for (const auto& e : *spans) {
        EXPECT_EQ(e.detector(), pc::DetectorKind::Ner);
        EXPECT_EQ(e.segment().value(), 0u);
        EXPECT_TRUE(pc::check_span(text, e.span()));
        EXPECT_TRUE(e.type() == pc::EntityType::Person || e.type() == pc::EntityType::Organization);
    }
    EXPECT_TRUE(std::is_sorted(spans->begin(), spans->end()));
}

// 조사 경계를 포함한 모든 fixture 에서 위치가 원문 byte 로 돌아가는지(오류 0)와 정답 수를 본다.
TEST(NerEngine, FixtureOffsetsMapBackToOriginalBytes) {
    std::size_t entities = 0;
    std::size_t errors = 0;
    std::size_t person_gold = 0;
    std::size_t person_hit = 0;
    std::size_t org_gold = 0;
    std::size_t org_hit = 0;
    for (const auto& f : fixtures()) {
        const auto spans = detect_once(f.text);
        ASSERT_TRUE(spans) << f.id;
        std::vector<Found> got;
        for (const auto& e : *spans) {
            ++entities;
            const auto begin = e.span().begin().value();
            const auto end = e.span().end().value();
            const bool ok = pc::check_span(f.text, e.span()) && f.text[begin] != ' ' && f.text[end - 1] != ' ';
            errors += ok ? 0 : 1;
            got.push_back({e.type(), f.text.substr(begin, end - begin)});
        }
        for (const auto& g : f.gold) {
            const auto hit = std::find(got.begin(), got.end(), g) != got.end();
            (g.type == pc::EntityType::Person ? person_gold : org_gold) += 1;
            (g.type == pc::EntityType::Person ? person_hit : org_hit) += hit ? 1 : 0;
        }
    }
    RecordProperty("entities", std::to_string(entities));
    RecordProperty("person_recall", std::to_string(person_hit) + "/" + std::to_string(person_gold));
    RecordProperty("org_recall", std::to_string(org_hit) + "/" + std::to_string(org_gold));
    EXPECT_GT(entities, 0u);
    EXPECT_EQ(errors, 0u);
    // D5 의 재현율 기준(PERSON 0.9, ORG 0.8)을 60건 합성 셋에서 먼저 확인한다. 큰 셋 측정은 Phase 7-3.
    EXPECT_GE(person_hit * 10, person_gold * 9);
    EXPECT_GE(org_hit * 10, org_gold * 8);
}

TEST(NerEngine, DecomposedHangulMapsBackToTheOriginalJamo) {
    // 조합형 자모(NFD)로 쓴 "김민수가": 보기에서는 음절로 합쳐지지만 결과는 원문 자모 byte 전체여야 한다.
    const std::string nfd =
        "\xE1\x84\x80\xE1\x85\xB5\xE1\x86\xB7"       // 김
        "\xE1\x84\x86\xE1\x85\xB5\xE1\x86\xAB"       // 민
        "\xE1\x84\x89\xE1\x85\xAE"                   // 수
        "\xE1\x84\x80\xE1\x85\xA1";                  // 가
    const std::string text = nfd + " 내일 회의에 참석합니다.";
    const auto spans = detect_once(text);
    ASSERT_TRUE(spans);
    ASSERT_EQ(spans->size(), 1u);
    EXPECT_EQ(spans->front().span().begin().value(), 0u);
    EXPECT_EQ(spans->front().span().end().value(), nfd.size() - 6);  // 끝의 "가" 두 자모를 뗀 위치
}

TEST(NerEngine, RangeLimitsTheScanButKeepsOriginalOffsets) {
    const std::string text = "이영희가 먼저 갔다. 김민수는 누리별테크에 다닌다.";
    const auto view = pd::make_view(text);
    ASSERT_TRUE(view);
    const auto split = text.find("김민수");
    const auto unit_of_split = static_cast<std::uint32_t>(pc::to_codepoint_offset(text, pc::Utf8ByteOffset{split})->value());
    const auto spans = engine().detect(text, pc::SegmentIndex{3}, *view,
                                       {unit_of_split, static_cast<std::uint32_t>(view->units.size())});
    ASSERT_TRUE(spans);
    ASSERT_EQ(spans->size(), 2u);
    EXPECT_EQ(spans->front().span().begin().value(), split);
    EXPECT_EQ(spans->front().segment().value(), 3u);
    for (const auto& e : *spans) {
        EXPECT_GE(e.span().begin().value(), split);
    }
}

TEST(NerEngine, InvalidRangeIsRejected) {
    const std::string text = "김민수가 왔다";
    const auto view = pd::make_view(text);
    ASSERT_TRUE(view);
    const auto n = static_cast<std::uint32_t>(view->units.size());
    EXPECT_EQ(engine().detect(text, pc::SegmentIndex{0}, *view, {0, n + 1}).error(), pn::NerError::InvalidSpan);
    EXPECT_EQ(engine().detect(text, pc::SegmentIndex{0}, *view, {3, 2}).error(), pn::NerError::InvalidSpan);
    const auto empty = engine().detect(text, pc::SegmentIndex{0}, *view, {2, 2});
    ASSERT_TRUE(empty);
    EXPECT_TRUE(empty->empty());
}

TEST(NerEngine, SpecialTokenTextInThePromptIsJustText) {
    const auto spans = detect_once("김민수 [SEP] [CLS] [PAD] 이영희가 왔다");
    ASSERT_TRUE(spans);
    for (const auto& e : *spans) {
        EXPECT_EQ(e.detector(), pc::DetectorKind::Ner);
    }
}

TEST(NerEngine, OverTheTokenLimitIsRejectedNotTruncated) {
    std::string big;
    for (int i = 0; i < 400; ++i) {
        big += "김민수는 누리별테크에 다닌다. ";
    }
    const auto spans = detect_once(big);
    ASSERT_FALSE(spans);
    EXPECT_EQ(spans.error(), pn::NerError::InputTooLong);
}

std::vector<pc::EntitySpan> detect_windows(const std::string& text) {
    const auto view = pd::make_view(text);
    EXPECT_TRUE(view);
    auto spans = engine().detect_all(text, pc::SegmentIndex{0}, *view);
    EXPECT_TRUE(spans);
    return spans.value_or(std::vector<pc::EntitySpan>{});
}

// 원문에서 needle 이 나온 모든 자리가 같은 종류의 결과 하나에 덮이는지.
void expect_every_occurrence_found(const std::string& text, const std::vector<pc::EntitySpan>& spans,
                                   const std::string& needle, pc::EntityType type) {
    std::size_t count = 0;
    for (auto at = text.find(needle); at != std::string::npos; at = text.find(needle, at + 1)) {
        ++count;
        const bool covered = std::ranges::any_of(spans, [&](const pc::EntitySpan& e) {
            return e.type() == type && e.span().begin().value() <= at &&
                   at + needle.size() <= e.span().begin().value() + e.span().size();
        });
        EXPECT_TRUE(covered) << needle << " @" << at;
    }
    EXPECT_GT(count, 0u);
}

TEST(NerEngine, LongTextIsSplitIntoSentenceWindows) {
    std::string big;
    for (int i = 0; i < 120; ++i) {
        big += "김민수는 누리별테크에 다닌다.\n";
    }
    ASSERT_EQ(detect_once(big).error(), pn::NerError::InputTooLong);  // 한 번에는 못 본다
    const auto spans = detect_windows(big);
    expect_every_occurrence_found(big, spans, "김민수", pc::EntityType::Person);
    expect_every_occurrence_found(big, spans, "누리별테크", pc::EntityType::Organization);
    EXPECT_EQ(spans.size(), 240u);  // 겹친 창이 없으니 중복도 없다
}

TEST(NerEngine, LongSentenceWithoutStopsStillFindsNamesAtWindowEdges) {
    // 문장 끝이 없는 긴 글은 32 토큰씩 겹쳐 밀며 본다. 이름이 창 경계 어디에 걸려도 한 창 안에서 온전히 보인다.
    std::string big;
    for (int i = 0; i < 60; ++i) {
        big += "오늘 회의에서 박서준 씨가 발표를 했고 ";
    }
    const auto spans = detect_windows(big);
    expect_every_occurrence_found(big, spans, "박서준", pc::EntityType::Person);
}

TEST(NerEngine, TooManyWindowsIsRefusedBeforeInference) {
    std::string big;
    for (int i = 0; i < 30'000; ++i) {
        big += "가 ";
    }
    const auto view = pd::make_view(big);
    ASSERT_TRUE(view);
    EXPECT_EQ(engine().detect_all(big, pc::SegmentIndex{0}, *view).error(), pn::NerError::TooManyWindows);
}

TEST(NerEngine, MissingOrChangedModelFilesMeanUnavailable) {
    const auto tmp = fs::temp_directory_path() / "pa_ner_engine_unavailable";
    fs::remove_all(tmp);
    fs::create_directories(tmp);
    EXPECT_EQ(pn::NerEngine::make(tmp).error(), pc::DetectError::Unavailable);  // 파일 없음
    EXPECT_EQ(pn::NerEngine::make(tmp / "none").error(), pc::DetectError::Unavailable);
    {
        std::ofstream(tmp / "tokenizer.json", std::ios::binary) << "{}";  // 해시가 다르다
        std::ofstream(tmp / "config.json", std::ios::binary) << "{}";
        std::ofstream(tmp / "model.onnx", std::ios::binary) << "x";
    }
    EXPECT_EQ(pn::NerEngine::make(tmp).error(), pc::DetectError::Unavailable);
    fs::remove_all(tmp);
}

TEST(NerEngine, UnreadableLabelConfigMeansUnavailable) {
    auto files = pn::read_verified_model_files(model_dir);
    ASSERT_TRUE(files);
    for (const std::string config : {"{}", R"({"id2label":{}})", R"({"id2label":{"0":"O","1":"B-NAME"}})",
                                     R"({"id2label":{"x":"O"}})", "not json"}) {
        auto changed = *files;
        changed.config = config;  // 확인 뒤에 바뀐 값을 넣어 label 해석만 따로 시험한다
        EXPECT_EQ(pn::NerEngine::make(changed, *pn::OrtEnv::create()).error(), pc::DetectError::Unavailable) << config;
    }
}

TEST(NerEngine, LabelCountMismatchIsUnavailable) {
    auto files = pn::read_verified_model_files(model_dir);
    ASSERT_TRUE(files);
    // 모델은 label 59개를 낸다. 설정이 다른 개수를 말하면 추론 결과를 해석하지 않고 거절한다.
    files->config = R"({"id2label":{"0":"O","1":"B-NAME","2":"I-NAME","3":"B-ORGANIZATION","4":"I-ORGANIZATION"}})";
    auto small = pn::NerEngine::make(*files, *pn::OrtEnv::create());
    ASSERT_TRUE(small);
    const std::string text = "김민수가 왔다";
    const auto view = pd::make_view(text);
    const auto result = small->detect(text, pc::SegmentIndex{0}, *view, {0, static_cast<std::uint32_t>(view->units.size())});
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error(), pn::NerError::Unavailable);
}
