// 추출 자식 실행기(ADR 0028): 정상 왕복, 실제 추출 실행 파일, 시간 상한, 출력 상한, 비정상 종료, 잘못된 출력, 취소.
#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stop_token>
#include <string>

#include "prompt_airlock/extract/runner.hpp"

namespace ex = prompt_airlock::extract;
using namespace std::chrono_literals;

namespace {

std::span<const std::byte> bytes(std::string_view s) { return std::as_bytes(std::span(s.data(), s.size())); }

}  // namespace

TEST(ExtractRunner, PassesTheWholeInputAndReadsTheResult) {
    const std::string big(3 << 20, 'a');  // 파이프 버퍼보다 큰 입력
    const auto result = ex::extract_in_child(PA_TEST_CHILD, "echo", bytes(big));
    ASSERT_TRUE(result && *result);
    EXPECT_EQ((*result)->blocks.at(0).text, std::to_string(big.size()));
}

TEST(ExtractRunner, RealExtractorReturnsTextOrReason) {
    const auto text = ex::extract_in_child(PA_EXTRACT_EXE, "txt", bytes("첫 줄\n둘째 줄"));
    ASSERT_TRUE(text && *text);
    EXPECT_EQ((*text)->blocks.size(), 2U);
    const auto broken = ex::extract_in_child(PA_EXTRACT_EXE, "doc", bytes("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"));
    ASSERT_TRUE(broken);
    EXPECT_EQ(broken->error(), ex::ExtractError::Damaged);  // 몸 없는 CFB
    // 이상한 확장자는 넘기지 않는다(내용으로만 판별).
    const auto odd = ex::extract_in_child(PA_EXTRACT_EXE, "--x y", bytes("글"));
    ASSERT_TRUE(odd && *odd);
}

TEST(ExtractRunner, FailuresAreClosed) {
    const ex::RunLimits quick{std::chrono::milliseconds(1500), 1U << 20};
    const auto start = std::chrono::steady_clock::now();
    EXPECT_EQ(ex::extract_in_child(PA_TEST_CHILD, "hang", bytes("x"), quick).error(), ex::RunError::Timeout);
    EXPECT_LT(std::chrono::steady_clock::now() - start, 10s);
    EXPECT_EQ(ex::extract_in_child(PA_TEST_CHILD, "flood", bytes("x"), quick).error(), ex::RunError::OutputTooLarge);
    EXPECT_EQ(ex::extract_in_child(PA_TEST_CHILD, "crash", bytes("x"), quick).error(), ex::RunError::Crashed);
    EXPECT_EQ(ex::extract_in_child(PA_TEST_CHILD, "garbage", bytes("x"), quick).error(), ex::RunError::BadOutput);
    EXPECT_EQ(ex::extract_in_child("no-such-extractor-binary", "txt", bytes("x"), quick).error(), ex::RunError::StartFailed);
}

TEST(ExtractRunner, CancelStopsTheChild) {
    // 이미 취소된 요청이면 자식을 기다리지 않고 죽인다(멈춘 자식이라도 바로 끝남).
    std::stop_source stop;
    stop.request_stop();
    const auto start = std::chrono::steady_clock::now();
    const auto result = ex::extract_in_child(PA_TEST_CHILD, "hang", bytes("x"), {}, stop.get_token());
    EXPECT_EQ(result.error(), ex::RunError::Cancelled);
    EXPECT_LT(std::chrono::steady_clock::now() - start, 10s);
}

// LaTeX·Typst 는 pandoc 으로 매크로·함수를 펼친다(결정 #239). pandoc 경로는 PA_TEST_PANDOC 으로 받고, 없으면 건너뛴다.
TEST(ExtractRunner, PandocExpandsMacrosAndRefusesOtherFiles) {
    const char* pandoc = std::getenv("PA_TEST_PANDOC");
    if (pandoc == nullptr) GTEST_SKIP() << "PA_TEST_PANDOC 없음";
    EXPECT_EQ(ex::markup_reader("tex"), "latex");
    EXPECT_EQ(ex::markup_reader("typ"), "typst");
    EXPECT_FALSE(ex::markup_reader("txt"));
    const auto latex = ex::convert_markup(pandoc, "latex",
                                          bytes(R"(\newcommand{\front}{900101}
\newcommand{\rrn}[2]{#1-#2}
\newcommand{\me}{\rrn{\front}{1234567}}
Number \me.
)"));
    ASSERT_TRUE(latex);
    EXPECT_NE(latex->find("900101-1234567"), std::string::npos) << *latex;
    const auto typst = ex::convert_markup(pandoc, "typst",
                                          bytes(R"(#let rrn(a, b) = [#a\-#b]
Number #rrn("900101", "1234567").
)"));
    ASSERT_TRUE(typst);
    EXPECT_NE(typst->find("900101-1234567"), std::string::npos) << *typst;
    // --sandbox: 다른 파일을 끼워 넣지 못한다. 실패하거나 내용이 빠져야 한다.
    const auto secret = std::filesystem::temp_directory_path() / "pa-pandoc-sandbox.tex";
    std::ofstream(secret) << "SANDBOXSECRET";
    const auto input = R"(\input{)" + secret.generic_string() + "}\n";
    const auto included = ex::convert_markup(pandoc, "latex", bytes(input));
    std::filesystem::remove(secret);
    EXPECT_TRUE(!included || included->find("SANDBOXSECRET") == std::string::npos);
}
