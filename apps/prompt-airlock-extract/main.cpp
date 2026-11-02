// 문서 추출 실행 파일(ADR 0028). 게이트웨이가 요청마다 띄운다.
//   prompt-airlock-extract --ext <확장자>    표준 입력: 파일 byte, 표준 출력: 버전 붙은 JSON 한 줄
// 파일을 해석하기 전에 자기 자원을 제한한다(Windows Job Object, Linux setrlimit). 제한을 걸지 못하면 해석하지 않는다.
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "prompt_airlock/extract/document.hpp"
#include "prompt_airlock/extract/runner.hpp"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <sys/resource.h>
#endif

namespace {

namespace ex = prompt_airlock::extract;

[[maybe_unused]] constexpr unsigned long long memory_limit = 1ULL << 30;  // #226 상한(sanitizer 빌드는 쓰지 않음)
constexpr unsigned cpu_seconds = 30;

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define PA_EXTRACT_SANITIZER 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define PA_EXTRACT_SANITIZER 1
#endif
#endif

bool limit_self() {
#ifdef _WIN32
    // 이 프로세스를 새 Job Object 에 넣는다. 핸들은 끝날 때까지 닫지 않는다(닫으면 KILL_ON_JOB_CLOSE 로 끝남).
    const HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr) {
        return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_TIME |
                                            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                                            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    info.BasicLimitInformation.ActiveProcessLimit = 1;  // 자식 프로세스를 만들 수 없다
    info.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = static_cast<LONGLONG>(cpu_seconds) * 10'000'000;
#ifndef PA_EXTRACT_SANITIZER
    info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    info.ProcessMemoryLimit = static_cast<SIZE_T>(memory_limit);
#endif
    return SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info)) != 0 &&
           AssignProcessToJobObject(job, GetCurrentProcess()) != 0;
#else
    const auto set = [](int resource, rlim_t value) {
        const rlimit lim{value, value};
        return setrlimit(resource, &lim) == 0;
    };
    // sanitizer 빌드는 그림자 메모리를 크게 예약하고 끝날 때 LeakSanitizer 가 fork 하므로
    // 주소 공간·프로세스 수 제한을 걸 수 없다(시험 빌드만 해당).
#ifndef PA_EXTRACT_SANITIZER
    if (!set(RLIMIT_AS, memory_limit) || !set(RLIMIT_NPROC, 0)) {
        return false;
    }
#endif
    return set(RLIMIT_CPU, cpu_seconds) && set(RLIMIT_FSIZE, 0) && set(RLIMIT_NOFILE, 16) && set(RLIMIT_CORE, 0);
#endif
}

}  // namespace

int main(int argc, char** argv) {
    std::string_view hint;
    if (argc == 3 && std::strcmp(argv[1], "--ext") == 0) {
        hint = argv[2];
    } else if (argc != 1) {
        std::fputs("usage: prompt-airlock-extract [--ext <extension>] < file > result.json\n", stderr);
        return 2;
    }
    if (!limit_self()) {
        return 3;  // 제한 없이 해석하지 않는다
    }
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    const ex::ExtractLimits limits;
    std::vector<std::byte> file;
    std::vector<char> buf(1 << 16);
    bool too_large = false;
    for (;;) {
        const auto n = std::fread(buf.data(), 1, buf.size(), stdin);
        if (n == 0) {
            break;
        }
        if (file.size() + n > limits.file_bytes) {
            too_large = true;
            break;
        }
        const auto* p = reinterpret_cast<const std::byte*>(buf.data());
        file.insert(file.end(), p, p + n);
    }
    const auto result = too_large ? std::expected<ex::ExtractedDocument, ex::ExtractError>(
                                        std::unexpected(ex::ExtractError::TooLarge))
                                  : ex::extract(file, hint, limits);
    const auto json = ex::to_json(result);
    if (std::fwrite(json.data(), 1, json.size(), stdout) != json.size() || std::fflush(stdout) != 0) {
        return 4;
    }
    return 0;
}
