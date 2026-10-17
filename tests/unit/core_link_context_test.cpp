#include "prompt_airlock/core/link_context.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace pc = prompt_airlock::core;
using pc::LinkContext;

namespace {

// 합성 token. 주소는 example.invalid 만 쓴다.
const std::string T = "\xE2\x9F\xA6PERSON_7Q2MK4XD9A\xE2\x9F\xA7";

// 응답 안 유일한 token 의 문맥.
LinkContext context_of(const std::string& response) {
    const auto tokens = pc::scan_tokens(response);
    EXPECT_EQ(tokens.size(), 1U) << response;
    if (tokens.size() != 1) {
        return LinkContext::None;
    }
    return pc::classify_link_contexts(response, tokens).front();
}

struct Case {
    std::string response;
    LinkContext expected;
};

void expect_all(const std::vector<Case>& cases) {
    for (const auto& c : cases) {
        EXPECT_EQ(context_of(c.response), c.expected) << c.response;
    }
}

}  // namespace

TEST(CoreLinkContext, MarkdownDestinationsAndReferences) {
    expect_all({
        {"[보기](https://example.invalid/?q=" + T + ")", LinkContext::MarkdownDestination},
        {"![x](" + T + ")", LinkContext::MarkdownDestination},
        {"[a](" + T + " 닫히지 않음", LinkContext::MarkdownDestination},
        {"[a](b(c)" + T + ")", LinkContext::MarkdownDestination},
        {"[1]: https://example.invalid/" + T, LinkContext::MarkdownReference},
        {"  [1]: " + T, LinkContext::MarkdownReference},
        {"![" + T + "](a.png)", LinkContext::None},  // 대체 글자
        {"[1] " + T + " 참고", LinkContext::None},
        {"[" + T + "] 참고: https://example.invalid", LinkContext::None},
    });
}

TEST(CoreLinkContext, AngleBracketsAndHtmlTags) {
    expect_all({
        {"<https://example.invalid/" + T + ">", LinkContext::HtmlTag},
        {"<" + T + ">", LinkContext::AngleBracket},
        {"<img src=\"https://example.invalid/" + T + "\">", LinkContext::HtmlTag},
        {"<a href=" + T + ">", LinkContext::HtmlTag},
        {"<span title=\"" + T + "\">", LinkContext::HtmlTag},
        {"<div style=\"background:url(" + T + ")\">", LinkContext::HtmlTag},
        {"<img alt=\"a>b\" src=" + T + ">", LinkContext::HtmlTag},  // 따옴표 안 '>'
        {"&lt;img src=" + T + "&gt;", LinkContext::HtmlTag},
        {"<a href=\"x\" " + T + " 닫히지 않음", LinkContext::HtmlTag},
        {T + " <b>굵게</b>", LinkContext::None},
        {"3 < " + T + " > 1", LinkContext::None},
    });
}

TEST(CoreLinkContext, UrlRuns) {
    expect_all({
        {"https://example.invalid/u/" + T, LinkContext::SchemeUrl},
        {"HTTPS://example.invalid/" + T, LinkContext::SchemeUrl},
        {T + "://x", LinkContext::SchemeUrl},
        {"mailto:" + T, LinkContext::SchemeUrl},
        {"tel:" + T, LinkContext::SchemeUrl},
        {"data:text/html," + T, LinkContext::SchemeUrl},
        {"(mailto:" + T + ")", LinkContext::SchemeUrl},
        {"www.example.invalid/" + T, LinkContext::WwwUrl},
        {"(www.example.invalid?" + T + ")", LinkContext::WwwUrl},
        {"example.invalid/" + T, LinkContext::HostPath},
        {"example.invalid:8080/" + T, LinkContext::HostPath},
        {T + " 님이 https://example.invalid 접속", LinkContext::None},
        {"metadata:" + T, LinkContext::None},  // 앞이 영문자라 data scheme 이 아님
        {"담당:" + T, LinkContext::None},
        {T + ", www 문서", LinkContext::None},
        {T + ".", LinkContext::None},
        {"v1.2/" + T, LinkContext::None},
    });
}

TEST(CoreLinkContext, CssUrls) {
    expect_all({
        {"url(" + T + ")", LinkContext::CssUrl},
        {"URL( \"" + T + "\" )", LinkContext::CssUrl},
        {"image-set(" + T + ")", LinkContext::CssUrl},
        {"@import '" + T + "'", LinkContext::CssUrl},
        {"curl(" + T + ")", LinkContext::None},
    });
}

TEST(CoreLinkContext, LinkTextIsJudgedApartFromAddress) {
    expect_all({
        {"[" + T + "](https://example.invalid/)", LinkContext::None},
        {"[가상 " + T + " 과장](https://example.invalid/a)", LinkContext::None},
        {"![" + T + "](https://example.invalid/a.png)", LinkContext::None},
        {"보기:[" + T + "](https://example.invalid/)", LinkContext::None},
        // 링크 글자 자체가 주소 모양이면 거절한다.
        {"[https://example.invalid/" + T + "](x)", LinkContext::SchemeUrl},
        {"[www.example.invalid/" + T + "](x)", LinkContext::WwwUrl},
        // 주소 쪽 token 은 그대로 거절한다.
        {"[보기](https://example.invalid/" + T + ")", LinkContext::MarkdownDestination},
        // 대괄호가 다른 줄에 있으면 링크 글자가 아니다.
        {"[\n" + T + "](https://example.invalid/)", LinkContext::SchemeUrl},
    });
}

TEST(CoreLinkContext, CheckRejectsWithoutNamingToken) {
    const std::string safe = "담당자는 " + T + " 입니다.";
    EXPECT_TRUE(pc::check_link_contexts(safe, pc::scan_tokens(safe)));

    const std::string unsafe = safe + " ![x](https://example.invalid/" + T + ")";
    const auto tokens = pc::scan_tokens(unsafe);
    const auto result = pc::check_link_contexts(unsafe, tokens);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().for_user(), (pc::UserRejection{pc::ReasonCode::ResponseTokenInLink, {}}));
    ASSERT_EQ(result.error().for_audit().findings.size(), 1U);
    EXPECT_EQ(std::get<pc::ResponseLocation>(result.error().for_audit().findings.front()).span, tokens[1].span);
}
