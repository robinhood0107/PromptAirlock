// purity 검사가 실제로 위반을 잡는지 확인하는 시험 입력이다. 빌드하지 않는다.
#include <fstream>
#include <chrono>

void write_log() {
    std::ofstream out("core.log");
    auto now = std::chrono::system_clock::now();
    (void)now;
}
