// ONNX 세션: 확인된 모델을 읽고 추론하며, 잘못된 모델은 예외 대신 값으로 거절한다.
#include "prompt_airlock/ner/session.hpp"

#include <gtest/gtest.h>

#include <vector>

#include "prompt_airlock/ner/model_files.hpp"
#include "prompt_airlock/ner/tokenizer.hpp"

namespace pc = prompt_airlock::core;
namespace pn = prompt_airlock::ner;

namespace {

const pn::VerifiedModelFiles& files() {
    static const auto loaded = pn::read_verified_model_files(PA_NER_MODEL_DIR);
    return *loaded;
}

std::shared_ptr<const pn::OrtEnv> env() {
    static const auto made = pn::OrtEnv::create();
    return *made;
}

std::vector<std::int64_t> ids_for(std::string_view text) {
    static const auto tokenizer = pn::WordPieceTokenizer::parse(files().tokenizer);
    const auto units = pc::decode_utf8(text);
    std::vector<std::int64_t> ids;
    for (const auto& token : tokenizer->encode(*units)) {
        ids.push_back(token.id);
    }
    return ids;
}

}  // namespace

TEST(NerSession, RunsTheVerifiedModel) {
    auto session = pn::OrtSession::create(env(), files().model);
    ASSERT_TRUE(session);
    const auto ids = ids_for("김민수가 내일 회의에 참석합니다.");
    const auto logits = session->run(ids);
    ASSERT_TRUE(logits);
    EXPECT_EQ(logits->length, ids.size());
    EXPECT_EQ(logits->labels, 59u);
    EXPECT_EQ(logits->values.size(), logits->length * logits->labels);
    for (std::size_t i = 0; i < logits->length; ++i) {
        EXPECT_LT(logits->argmax(i), logits->labels);
    }
}

TEST(NerSession, SameInputGivesSameLogits) {
    auto session = pn::OrtSession::create(env(), files().model);
    ASSERT_TRUE(session);
    const auto ids = ids_for("박서준을 만났다.");
    const auto first = session->run(ids);
    const auto second = session->run(ids);
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    EXPECT_EQ(first->values, second->values);
}

TEST(NerSession, MovedSessionStillRuns) {
    auto created = pn::OrtSession::create(env(), files().model);
    ASSERT_TRUE(created);
    pn::OrtSession moved = std::move(*created);
    EXPECT_TRUE(moved.run(ids_for("이영희는 보고서를 제출했다.")));
}

TEST(NerSession, SessionsShareOneEnvironment) {
    auto first = pn::OrtSession::create(env(), files().model);
    auto second = pn::OrtSession::create(env(), files().model);
    ASSERT_TRUE(first);
    ASSERT_TRUE(second);
    const auto ids = ids_for("김민수가 왔다.");
    EXPECT_EQ(first->run(ids)->values, second->run(ids)->values);
    EXPECT_EQ(pn::OrtSession::create(nullptr, files().model).error(), pn::SessionError::Load);
}

TEST(NerSession, InvalidModelBytesAreRejectedAsValues) {
    const std::vector<std::byte> garbage(64, std::byte{0x42});
    ASSERT_FALSE(pn::OrtSession::create(env(), garbage));
    EXPECT_EQ(pn::OrtSession::create(env(), garbage).error(), pn::SessionError::Load);
    EXPECT_EQ(pn::OrtSession::create(env(), {}).error(), pn::SessionError::Load);
}

TEST(NerSession, EmptyInputFailsAsAValue) {
    auto session = pn::OrtSession::create(env(), files().model);
    ASSERT_TRUE(session);
    const std::vector<std::int64_t> none;
    const auto logits = session->run(none);
    ASSERT_FALSE(logits);
    EXPECT_TRUE(logits.error() == pn::SessionError::Run || logits.error() == pn::SessionError::BadOutput);
}

TEST(NerSession, OutOfVocabIdFailsAsAValue) {
    auto session = pn::OrtSession::create(env(), files().model);
    ASSERT_TRUE(session);
    const std::vector<std::int64_t> ids{2, 9'999'999, 3};
    EXPECT_FALSE(session->run(ids));
}
