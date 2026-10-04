// [[clang::lifetimebound]] 를 붙이면 같은 실수를 컴파일 시점에 경고하는지 확인한다(구문 검사 전용).
#include <string>
#include <string_view>

namespace {

std::string make_prompt() { return "김민수 과장"; }

std::string_view head(std::string_view text [[clang::lifetimebound]]) { return text.substr(0, 3); }

}  // namespace

std::size_t use() {
    const std::string_view kept = head(make_prompt());
    return kept.size();
}
