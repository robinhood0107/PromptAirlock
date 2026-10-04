// 의도된 결함 예제: 임시 문자열을 가리키는 string_view 를 보관한 뒤 읽는다.
// 주석이 없는 API 라 컴파일러 경고 없이 빌드되고, ASan 이 실행 중에 잡아야 한다.
#include <cstdio>
#include <string>
#include <string_view>

namespace {

std::string make_prompt() { return std::string(64, 'x') + " 김민수"; }

std::string_view tail(std::string_view text) { return text.substr(text.size() - 9); }

}  // namespace

int main() {
    const std::string_view kept = tail(make_prompt());  // 임시 std::string 은 이 문장 끝에서 소멸한다.
    std::printf("%c\n", kept.front());
    return 0;
}
