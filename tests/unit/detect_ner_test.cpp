// 탐지기와 NER 연결: 가짜 NER 로 결과 합치기, 오류 전파(fail closed), 개인 표지, 인코딩을 푼 텍스트를 본다.
#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;

namespace {

// text 안의 name 이 나오는 자리를 모두 사람 이름으로 돌려준다. error 가 있으면 그 오류를 낸다.
class FakeNer final : public pd::NerScanner {
public:
    explicit FakeNer(std::string name, std::optional<pc::DetectError> error = std::nullopt)
        : name_(std::move(name)), error_(error) {}

    std::expected<std::vector<pc::EntitySpan>, pc::DetectError> scan(std::string_view text, pc::SegmentIndex segment,
                                                                     const pd::DetectionView&) const override {
        if (error_) {
            return std::unexpected(*error_);
        }
        std::vector<pc::EntitySpan> out;
        for (auto at = text.find(name_); at != std::string_view::npos; at = text.find(name_, at + 1)) {
            const auto span = *pc::ByteSpan::make(pc::Utf8ByteOffset{at}, pc::Utf8ByteOffset{at + name_.size()});
            out.push_back(*pc::EntitySpan::make(text, segment, span, pc::EntityType::Person, pc::DetectorKind::Ner));
        }
        return out;
    }

private:
    std::string name_;
    std::optional<pc::DetectError> error_;
};

pd::Detectors with_ner(std::shared_ptr<const pd::NerScanner> ner) { return *pd::Detectors::make({}, std::move(ner)); }

std::vector<std::pair<pc::EntityType, std::string>> found(const pd::Detectors& d, std::string_view text) {
    const auto entities = d.detect_segment(text, pc::SegmentIndex{0});
    EXPECT_TRUE(entities);
    std::vector<std::pair<pc::EntityType, std::string>> out;
    for (const auto& e : *entities) {
        out.emplace_back(e.type(), std::string(text.substr(e.span().begin().value(), e.span().size())));
    }
    return out;
}

pc::PromptDocument document(std::string_view text) {
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts));
    return *std::move(builder).build();
}

}  // namespace

TEST(DetectNer, NamesJoinTheDeterministicResults) {
    const auto d = with_ner(std::make_shared<FakeNer>("김민수"));
    const std::string text = "김민수 메일은 kim@example.com 입니다.";
    const auto result = found(d, text);
    EXPECT_EQ(result, (std::vector<std::pair<pc::EntityType, std::string>>{
                          {pc::EntityType::Person, "김민수"}, {pc::EntityType::Email, "kim@example.com"}}));
    const auto entities = d.detect_segment(text, pc::SegmentIndex{0});
    EXPECT_EQ(entities->front().detector(), pc::DetectorKind::Ner);
}

TEST(DetectNer, WithoutNerOnlyRulesRun) {
    const auto d = *pd::Detectors::make({});
    EXPECT_EQ(found(d, "김민수 메일은 kim@example.com 입니다.").size(), 1u);
}

TEST(DetectNer, NerFailureFailsTheWholeDetection) {
    for (const auto error : {pc::DetectError::Unavailable, pc::DetectError::Overloaded}) {
        const auto d = with_ner(std::make_shared<FakeNer>("김민수", error));
        EXPECT_EQ(d.detect_segment("아무 글", pc::SegmentIndex{0}).error(), error);
        EXPECT_EQ(d.detect(document("아무 글")).error(), error);
    }
}

TEST(DetectNer, NerPersonMarksASensitiveSentence) {
    // 호칭·직함이 없어 결정론 규칙만으로는 특정 개인을 알 수 없는 문장이다.
    const std::string text = "김민수는 당뇨 치료 중입니다.";
    const auto plain = found(*pd::Detectors::make({}), text);
    EXPECT_TRUE(std::ranges::none_of(plain, [](const auto& p) { return p.first == pc::EntityType::SensitivePersonalInfo; }));
    const auto marked = found(with_ner(std::make_shared<FakeNer>("김민수")), text);
    EXPECT_TRUE(std::ranges::any_of(marked, [](const auto& p) { return p.first == pc::EntityType::SensitivePersonalInfo; }));
}

TEST(DetectNer, DecodedTextIsAlsoScanned) {
    // "김민수 왔다" 의 base64. 푼 텍스트에서 찾은 종류가 인코딩 결과의 대상에 들어간다.
    const auto d = with_ner(std::make_shared<FakeNer>("김민수"));
    const auto detection = d.detect(document("메모: 6rmA66+87IiYIOyZlOuLpA=="));
    ASSERT_TRUE(detection);
    ASSERT_EQ(detection->encoded.size(), 1u);
    EXPECT_TRUE(detection->encoded.front().targets.contains(pc::EntityType::Person));
}

TEST(DetectNer, SameInputGivesSameResult) {
    const auto d = with_ner(std::make_shared<FakeNer>("김민수"));
    const std::string text = "김민수와 김민수가 만났다. 010-2345-6789";
    EXPECT_EQ(found(d, text), found(d, text));
}
