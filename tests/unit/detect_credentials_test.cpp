// 인증 정보: 표지어 뒤 값, 접속 문자열, ID/PW 짝, URL userinfo, HTTP Basic, 계정 문맥 + 무작위성. 값은 합성이다.
#include "prompt_airlock/detect/detectors.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;

namespace {

std::vector<std::string> credentials(std::string_view text) {
    static const auto d = *pd::Detectors::make({});
    std::vector<std::string> out;
    const auto entities = d.detect_segment(text, pc::SegmentIndex{0});
    EXPECT_TRUE(entities);
    for (const auto& e : *entities) {
        if (e.type() == pc::EntityType::Credential) {
            out.emplace_back(text.substr(e.span().begin().value(), e.span().size()));
        }
    }
    return out;
}

}  // namespace

TEST(DetectCredentials, Positives) {
    const std::vector<std::pair<std::string_view, std::string_view>> cases = {
        {"비밀번호: hunter2", "hunter2"},
        {"비밀번호는 abc123! 입니다", "abc123!"},
        {"인증번호는 482913 입니다", "482913"},
        {"PW=Qwer1234", "Qwer1234"},
        {"the password is s3cret.", "s3cret"},
        {"Server=db;User Id=sa;Password=P@ssw0rd;", "P@ssw0rd"},
        {"ID: user01 / PW: Abcd1234", "user01"},
        {"ID: user01 / PW: Abcd1234", "Abcd1234"},
        {"https://admin:pa55@example.invalid/x", "admin:pa55"},
        {"Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
        {"로그인 계정 정보 Xy7#mK2pQ", "Xy7#mK2pQ"},
        {"パスワード：abc123", "abc123"},
    };
    for (const auto& [text, value] : cases) {
        const auto found = credentials(text);
        EXPECT_NE(std::ranges::find(found, std::string(value)), found.end()) << text;
    }
}

TEST(DetectCredentials, Negatives) {
    for (const std::string_view text : {
             "비밀번호를 잊어버렸어요",
             "비밀번호는 주기적으로 바꾸세요",
             "password is required",
             "비밀번호: 재설정 필요",
             "basic understanding of Python3",
             "로그인 화면에서 Windows11! 설치",
             "https://example.invalid:8443/path",
             "ID: user01 만 알려 드립니다",
             "passcode2 field",
         }) {
        EXPECT_TRUE(credentials(text).empty()) << text;
    }
}
