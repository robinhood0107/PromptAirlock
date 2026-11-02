// 실행기 시험용 자식. "--ext <방식>" 의 방식대로 일부러 잘못 행동한다.
//   hang: 입력을 다 읽고 멈춤, crash: 0 이 아닌 종료, flood: 출력을 끝없이, garbage: JSON 이 아닌 출력,
//   echo: 받은 byte 수를 글자로 돌려줌(정상 JSON)
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

int main(int argc, char** argv) {
    if (argc != 3 || std::strcmp(argv[1], "--ext") != 0) {
        return 2;
    }
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
#endif
    const std::string mode = argv[2];
    std::size_t total = 0;
    std::vector<char> buf(1 << 16);
    for (std::size_t n; (n = std::fread(buf.data(), 1, buf.size(), stdin)) > 0;) {
        total += n;
    }
    if (mode == "hang") {
        std::mutex m;
        std::condition_variable never;
        std::unique_lock lock(m);
        never.wait(lock, [] { return false; });
    }
    if (mode == "crash") {
        return 7;
    }
    if (mode == "flood") {
        const std::string chunk(1 << 16, 'x');
        for (;;) {
            if (std::fwrite(chunk.data(), 1, chunk.size(), stdout) != chunk.size()) {
                return 1;
            }
        }
    }
    if (mode == "garbage") {
        std::fputs("not json", stdout);
        return 0;
    }
    std::printf(R"({"v":1,"ok":true,"format":"txt","blocks":[{"at":"line1","text":"%zu"}],"omitted":{"comments":0,"revisions":0,"hidden":0,"other_parts":0}})",
                total);
    return 0;
}
