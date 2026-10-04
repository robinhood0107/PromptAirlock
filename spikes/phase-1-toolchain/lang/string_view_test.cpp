// string_view 를 안전하게 쓰는 대안을 확인한다. 결함 예제는 dangling_view_demo.cpp 에 따로 둔다.
#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

namespace {

std::string make_prompt() { return "김민수 과장에게 연락"; }

// 대안 1: 호출자가 원본 수명을 소유하고, view 는 동기 범위 안에서만 쓴다.
std::string_view first_token(std::string_view text) {
    const auto pos = text.find(' ');
    return text.substr(0, pos);
}

// 대안 2: 결과를 오래 보관해야 하면 소유 타입으로 돌려준다.
std::string first_token_owned(std::string_view text) { return std::string{first_token(text)}; }

// 대안 3: 원문 대신 offset 만 저장한다. 원문은 소유자가 따로 들고 있다.
struct ByteSpan {
    std::size_t start;
    std::size_t end;
};

ByteSpan first_token_span(std::string_view text) {
    const auto pos = text.find(' ');
    return {0, pos == std::string_view::npos ? text.size() : pos};
}

}  // namespace

TEST(StringView, ViewWithinOwnerScope) {
    const std::string owner = make_prompt();
    const std::string_view head = first_token(owner);
    EXPECT_EQ(head, "김민수");
}

TEST(StringView, OwnedResultOutlivesTemporary) {
    const std::string head = first_token_owned(make_prompt());
    EXPECT_EQ(head, "김민수");
}

TEST(StringView, OffsetInsteadOfView) {
    std::vector<ByteSpan> spans;
    const std::string owner = make_prompt();
    spans.push_back(first_token_span(owner));
    const auto& s = spans.front();
    EXPECT_EQ(std::string_view(owner).substr(s.start, s.end - s.start), "김민수");
    // UTF-8 byte offset 이다. 한글 3자는 9바이트다.
    EXPECT_EQ(s.end, 9u);
}
