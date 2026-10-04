// 환경 점검용 C++23 최소 프로그램.
// 인자 없이 실행하면 정상 경로만 돈다. sanitizer 동작 확인용으로 의도된 결함 모드를 둔다.
#include <cstdio>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

enum class ParseError { Empty, NotDigit };

std::expected<int, ParseError> parse_digit(std::string_view text) {
    if (text.empty()) {
        return std::unexpected(ParseError::Empty);
    }
    if (text.front() < '0' || text.front() > '9') {
        return std::unexpected(ParseError::NotDigit);
    }
    return text.front() - '0';
}

int run_normal() {
    const auto ok = parse_digit("7").transform([](int v) { return v * 2; });
    const auto bad = parse_digit("x");
    if (!ok || *ok != 14 || bad || bad.error() != ParseError::NotDigit) {
        std::puts("expected_smoke: FAIL");
        return 1;
    }
    std::puts("expected_smoke: OK");
    return 0;
}

// ASan 확인: 해제된 버퍼를 읽는다.
int run_use_after_free() {
    auto data = std::make_unique<std::vector<int>>(4, 1);
    int* p = data->data();
    data.reset();
    return p[0];
}

// UBSan 확인: 부호 있는 정수 overflow.
int run_signed_overflow(int base) {
    int v = base;
    v += 1;
    return v;
}

// TSan 확인: 동기화 없는 공유 변수 쓰기.
int run_race() {
    int shared = 0;
    std::thread a([&] { for (int i = 0; i < 100000; ++i) ++shared; });
    std::thread b([&] { for (int i = 0; i < 100000; ++i) ++shared; });
    a.join();
    b.join();
    return shared > 0 ? 0 : 1;
}

}  // namespace


int main(int argc, char** argv) {
    const std::string_view mode = argc > 1 ? argv[1] : "";
    if (mode == "--uaf") return run_use_after_free();
    if (mode == "--overflow") return run_signed_overflow(argc > 2 ? 2147483647 : 0) == 0 ? 1 : 0;
    if (mode == "--race") return run_race();
    return run_normal();
}
