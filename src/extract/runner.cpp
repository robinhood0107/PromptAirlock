// 추출 자식 실행기. 쓰기 스레드가 파일 byte 를 자식 stdin 에 넣고 닫고, 읽기 스레드가 stdout 을 상한까지 모은다.
// 이 스레드는 마감 시각·취소·읽기 끝 가운데 먼저 오는 것을 기다리고, 끝나지 않았으면 자식을 죽인다.
// 자식 stderr 는 버린다(원문 조각이 섞일 수 있음).
#include "prompt_airlock/extract/runner.hpp"

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
extern char** environ;
#endif

namespace prompt_airlock::extract {

std::filesystem::path default_executable() {
#ifdef _WIN32
    std::wstring path(32768, L'\0');
    const auto size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (size == 0 || size >= path.size()) return {};
    path.resize(size);
    return std::filesystem::path(path).parent_path() / L"prompt-airlock-extract.exe";
#else
    std::string path(4096, '\0');
    const auto size = readlink("/proc/self/exe", path.data(), path.size());
    if (size <= 0 || static_cast<std::size_t>(size) >= path.size()) return {};
    path.resize(static_cast<std::size_t>(size));
    return std::filesystem::path(path).parent_path() / "prompt-airlock-extract";
#endif
}

namespace {

#ifdef _WIN32
struct Handle {
    HANDLE h = nullptr;
    Handle() = default;
    explicit Handle(HANDLE v) : h(v == INVALID_HANDLE_VALUE ? nullptr : v) {}
    Handle(Handle&& o) noexcept : h(std::exchange(o.h, nullptr)) {}
    Handle& operator=(Handle&& o) noexcept {
        reset();
        h = std::exchange(o.h, nullptr);
        return *this;
    }
    ~Handle() { reset(); }
    void reset() noexcept {
        if (h != nullptr) {
            CloseHandle(h);
            h = nullptr;
        }
    }
    explicit operator bool() const noexcept { return h != nullptr; }
};

struct Child {
    Handle process;
    Handle in;   // 자식 stdin 쓰기 끝
    Handle out;  // 자식 stdout 읽기 끝

    bool write_all(std::span<const std::byte> data) {
        while (!data.empty()) {
            DWORD wrote = 0;
            const auto chunk = static_cast<DWORD>(std::min<std::size_t>(data.size(), 1U << 20));
            if (!WriteFile(in.h, data.data(), chunk, &wrote, nullptr) || wrote == 0) {
                return false;  // 자식이 먼저 끝났거나 죽음
            }
            data = data.subspan(wrote);
        }
        return true;
    }
    void close_in() noexcept { in.reset(); }
    // 0 은 끝(EOF), 음수는 오류.
    long read_some(char* buf, std::size_t size) {
        DWORD got = 0;
        if (!ReadFile(out.h, buf, static_cast<DWORD>(size), &got, nullptr)) {
            return GetLastError() == ERROR_BROKEN_PIPE ? 0 : -1;
        }
        return static_cast<long>(got);
    }
    void kill() noexcept { TerminateProcess(process.h, 1); }
    int wait() noexcept {
        WaitForSingleObject(process.h, INFINITE);
        DWORD code = 1;
        GetExitCodeProcess(process.h, &code);
        return static_cast<int>(code);
    }
};

void append_quoted(std::wstring& cmd, const std::wstring& arg) {
    cmd += L'"';
    for (const wchar_t c : arg) {
        if (c == L'"') {
            cmd += L'\\';
        }
        cmd += c;
    }
    cmd += L'"';
}

std::expected<Child, RunError> spawn(const std::filesystem::path& exe, const std::vector<std::string>& args) {
    SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE r = nullptr;
    HANDLE w = nullptr;
    if (!CreatePipe(&r, &w, &inherit, 0)) {
        return std::unexpected(RunError::StartFailed);
    }
    Handle in_read(r), in_write(w);
    if (!CreatePipe(&r, &w, &inherit, 0)) {
        return std::unexpected(RunError::StartFailed);
    }
    Handle out_read(r), out_write(w);
    SetHandleInformation(in_write.h, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(out_read.h, HANDLE_FLAG_INHERIT, 0);
    Handle err(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr));
    if (!err) {
        return std::unexpected(RunError::StartFailed);
    }
    // 상속 핸들을 이 셋으로 제한한다(동시에 띄운 다른 자식의 파이프를 물려받지 않게).
    HANDLE inherit_list[3] = {in_read.h, out_write.h, err.h};
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    std::vector<std::byte> attr_buf(attr_size);
    auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)) {
        return std::unexpected(RunError::StartFailed);
    }
    struct AttrGuard {
        LPPROC_THREAD_ATTRIBUTE_LIST a;
        ~AttrGuard() { DeleteProcThreadAttributeList(a); }
    } attr_guard{attrs};
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit_list, sizeof(inherit_list),
                                   nullptr, nullptr)) {
        return std::unexpected(RunError::StartFailed);
    }
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = in_read.h;
    si.StartupInfo.hStdOutput = out_write.h;
    si.StartupInfo.hStdError = err.h;
    si.lpAttributeList = attrs;
    std::wstring cmd;
    append_quoted(cmd, exe.wstring());
    for (const auto& arg : args) {
        cmd += L' ';
        append_quoted(cmd, std::wstring(arg.begin(), arg.end()));  // 인자는 고정 ASCII 와 영문·숫자 확장자뿐이다
    }
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe.wstring().c_str(), cmd.data(), nullptr, nullptr, TRUE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, nullptr, nullptr, &si.StartupInfo, &pi)) {
        return std::unexpected(RunError::StartFailed);
    }
    CloseHandle(pi.hThread);
    return Child{Handle(pi.hProcess), std::move(in_write), std::move(out_read)};
}
#else
struct Fd {
    int fd = -1;
    Fd() = default;
    explicit Fd(int v) : fd(v) {}
    Fd(Fd&& o) noexcept : fd(std::exchange(o.fd, -1)) {}
    Fd& operator=(Fd&& o) noexcept {
        reset();
        fd = std::exchange(o.fd, -1);
        return *this;
    }
    ~Fd() { reset(); }
    void reset() noexcept {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }
};

struct Child {
    pid_t pid = -1;
    Fd in;
    Fd out;
    bool reaped = false;

    bool write_all(std::span<const std::byte> data) {
        // 자식이 먼저 끝나면 SIGPIPE 가 이 스레드로 온다. 이 스레드에서만 막고, 스레드가 끝나면 걸린 신호는 버려진다.
        sigset_t pipe_only;
        sigemptyset(&pipe_only);
        sigaddset(&pipe_only, SIGPIPE);
        pthread_sigmask(SIG_BLOCK, &pipe_only, nullptr);
        while (!data.empty()) {
            const auto n = ::write(in.fd, data.data(), std::min<std::size_t>(data.size(), 1U << 20));
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n <= 0) {
                return false;
            }
            data = data.subspan(static_cast<std::size_t>(n));
        }
        return true;
    }
    void close_in() noexcept { in.reset(); }
    long read_some(char* buf, std::size_t size) {
        for (;;) {
            const auto n = ::read(out.fd, buf, size);
            if (n < 0 && errno == EINTR) {
                continue;
            }
            return static_cast<long>(n);
        }
    }
    void kill() noexcept { ::kill(pid, SIGKILL); }
    int wait() noexcept {
        int status = 0;
        while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
        reaped = true;
        return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    }
};

std::expected<Child, RunError> spawn(const std::filesystem::path& exe, const std::vector<std::string>& args) {
    int in_pipe[2];
    int out_pipe[2];
    if (::pipe2(in_pipe, O_CLOEXEC) != 0) {
        return std::unexpected(RunError::StartFailed);
    }
    Fd in_read(in_pipe[0]), in_write(in_pipe[1]);
    if (::pipe2(out_pipe, O_CLOEXEC) != 0) {
        return std::unexpected(RunError::StartFailed);
    }
    Fd out_read(out_pipe[0]), out_write(out_pipe[1]);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, in_read.fd, 0);
    posix_spawn_file_actions_adddup2(&actions, out_write.fd, 1);
    posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);
    const std::string path = exe.string();
    std::vector<char*> argv{const_cast<char*>(path.c_str())};
    for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);
    pid_t pid = -1;
    const int rc = posix_spawn(&pid, path.c_str(), &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        return std::unexpected(RunError::StartFailed);
    }
    return Child{pid, std::move(in_write), std::move(out_read)};
}
#endif

// 자식을 띄워 file 을 stdin 에 넣고 stdout 전부를 받는다. 시간·출력 상한·취소·0 아닌 종료는 실패.
std::expected<std::string, RunError> run_child(const std::filesystem::path& exe, const std::vector<std::string>& args,
                                               std::span<const std::byte> file, const RunLimits& limits,
                                               std::stop_token stop) {
    auto child = spawn(exe, args);
    if (!child) {
        return std::unexpected(child.error());
    }
    std::mutex mutex;
    std::condition_variable_any changed;
    bool read_done = false;
    bool overflow = false;
    std::string output;
    {
        std::jthread writer([&] {
            (void)child->write_all(file);
            child->close_in();
        });
        std::jthread reader([&] {
            std::vector<char> buf(64 * 1024);
            for (;;) {
                const auto n = child->read_some(buf.data(), buf.size());
                if (n <= 0) {
                    break;
                }
                if (output.size() + static_cast<std::size_t>(n) > limits.output_bytes) {
                    const std::lock_guard lock(mutex);
                    overflow = true;
                    break;
                }
                output.append(buf.data(), static_cast<std::size_t>(n));
            }
            const std::lock_guard lock(mutex);
            read_done = true;
            changed.notify_all();
        });
        std::unique_lock lock(mutex);
        const bool finished = changed.wait_until(lock, stop, std::chrono::steady_clock::now() + limits.time,
                                                 [&] { return read_done; });
        const bool stopped = stop.stop_requested();
        if (!finished || overflow) {
            child->kill();
        }
        lock.unlock();
        // 스레드는 여기서 합류한다. 죽였으면 파이프가 닫혀 읽기·쓰기가 곧 끝난다.
        reader.join();
        writer.join();
        const int code = child->wait();
        if (!finished) {
            return std::unexpected(stopped ? RunError::Cancelled : RunError::Timeout);
        }
        if (overflow) {
            return std::unexpected(RunError::OutputTooLarge);
        }
        if (code != 0) {
            return std::unexpected(RunError::Crashed);
        }
    }
    return output;
}

}  // namespace

ChildResult extract_in_child(const std::filesystem::path& exe, std::string_view name_hint,
                             std::span<const std::byte> file, const RunLimits& limits, std::stop_token stop) {
    if (!std::ranges::all_of(name_hint, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }) ||
        name_hint.size() > 8) {
        name_hint = {};  // 이상한 확장자는 넘기지 않고 내용으로만 판별하게 한다
    }
    auto output = run_child(exe, {"--ext", std::string(name_hint)}, file, limits, stop);
    if (!output) return std::unexpected(output.error());
    return from_json(*output);
}

std::optional<std::string_view> markup_reader(std::string_view extension) noexcept {
    if (extension == "tex" || extension == "latex") return "latex";
    if (extension == "typ") return "typst";
    return std::nullopt;
}

std::expected<std::string, RunError> convert_markup(const std::filesystem::path& pandoc, std::string_view reader,
                                                    std::span<const std::byte> file, const RunLimits& limits,
                                                    std::stop_token stop) {
    // --sandbox: 다른 파일(\input, #include, 그림)·네트워크를 읽지 않는다. +RTS -M: pandoc 자체 메모리 상한(1 GiB).
    return run_child(pandoc,
                     {"--sandbox", "--from", std::string(reader), "--to", "plain", "--wrap=none", "+RTS", "-M1024m",
                      "-RTS"},
                     file, limits, stop);
}

}  // namespace prompt_airlock::extract
