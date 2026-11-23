// 추출 자식 실행기. 쓰기 스레드가 파일 byte 를 자식 stdin 에 넣고 닫고, 읽기 스레드가 stdout 을 상한까지 모은다.
// 이 스레드는 마감 시각·취소·읽기 끝 가운데 먼저 오는 것을 기다리고, 끝나지 않았으면 자식을 죽인다.
// 자식 stderr 는 버린다(원문 조각이 섞일 수 있음).
#include "prompt_airlock/extract/runner.hpp"

#include <algorithm>
#include <condition_variable>
#include <map>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <cwchar>
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
    Handle job;

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
    void kill() noexcept {
        if (job) TerminateJobObject(job.h, 1);
        if (process) TerminateProcess(process.h, 1);
    }
    bool wait_for_exit_notification() noexcept { return WaitForSingleObject(process.h, INFINITE) == WAIT_OBJECT_0; }
    std::expected<int, RunError> wait() noexcept {
        if (WaitForSingleObject(process.h, INFINITE) != WAIT_OBJECT_0) {
            return std::unexpected(RunError::Crashed);
        }
        DWORD code = 1;
        if (!GetExitCodeProcess(process.h, &code)) return std::unexpected(RunError::Crashed);
        return static_cast<int>(code);
    }
};

std::wstring widen(std::string_view text) {
    if (text.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size) != size) {
        return {};
    }
    return result;
}

std::expected<std::vector<wchar_t>, RunError> make_environment_block(const std::vector<std::string>& entries) {
    std::map<std::wstring, std::wstring, decltype([](const std::wstring& a, const std::wstring& b) {
                 return _wcsicmp(a.c_str(), b.c_str()) < 0;
             })> values;
    for (const auto& entry : entries) {
        const auto equals = entry.find('=');
        if (equals == std::string::npos || equals == 0) return std::unexpected(RunError::StartFailed);
        auto name = widen(std::string_view(entry).substr(0, equals));
        auto value = widen(std::string_view(entry).substr(equals + 1));
        if (name.empty() || !values.emplace(std::move(name), std::move(value)).second) {
            return std::unexpected(RunError::StartFailed);
        }
    }
    std::vector<wchar_t> block;
    for (const auto& [name, value] : values) {
        block.insert(block.end(), name.begin(), name.end());
        block.push_back(L'=');
        block.insert(block.end(), value.begin(), value.end());
        block.push_back(L'\0');
    }
    if (block.empty()) block.push_back(L'\0');
    block.push_back(L'\0');
    return block;
}

void append_quoted(std::wstring& cmd, const std::wstring& arg) {
    cmd.push_back(L'"');
    std::size_t backslashes = 0;
    for (const wchar_t c : arg) {
        if (c == L'\\') {
            ++backslashes;
        } else if (c == L'"') {
            cmd.append(backslashes * 2 + 1, L'\\');
            cmd.push_back(c);
            backslashes = 0;
        } else {
            cmd.append(backslashes, L'\\');
            cmd.push_back(c);
            backslashes = 0;
        }
    }
    cmd.append(backslashes * 2, L'\\');
    cmd.push_back(L'"');
}

std::expected<Child, RunError> spawn(const std::filesystem::path& exe, const std::vector<std::string>& args,
                                    const ChildLaunchOptions& launch, bool contain_children) {
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
    std::vector<wchar_t> environment;
    if (!launch.inherit_environment) {
        auto block = make_environment_block(launch.environment);
        if (!block) return std::unexpected(block.error());
        environment = std::move(*block);
    }
    Handle job;
    if (contain_children) {
        job = Handle(CreateJobObjectW(nullptr, nullptr));
        if (!job) return std::unexpected(RunError::StartFailed);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &info, sizeof(info))) {
            return std::unexpected(RunError::StartFailed);
        }
    }
    std::wstring cmd;
    append_quoted(cmd, exe.wstring());
    for (const auto& arg : args) {
        cmd += L' ';
        const auto wide_arg = widen(arg);
        if (!arg.empty() && wide_arg.empty()) return std::unexpected(RunError::StartFailed);
        append_quoted(cmd, wide_arg);
    }
    PROCESS_INFORMATION pi{};
    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
    if (!launch.inherit_environment) flags |= CREATE_UNICODE_ENVIRONMENT;
    if (contain_children) flags |= CREATE_SUSPENDED;
    const std::wstring working_directory = launch.working_directory.empty() ? std::wstring{} : launch.working_directory.wstring();
    if (!CreateProcessW(exe.wstring().c_str(), cmd.data(), nullptr, nullptr, TRUE, flags,
                        launch.inherit_environment ? nullptr : environment.data(),
                        working_directory.empty() ? nullptr : working_directory.c_str(), &si.StartupInfo, &pi)) {
        return std::unexpected(RunError::StartFailed);
    }
    Handle process(pi.hProcess), thread(pi.hThread);
    if (contain_children &&
        (!AssignProcessToJobObject(job.h, process.h) || ResumeThread(thread.h) == static_cast<DWORD>(-1))) {
        TerminateProcess(process.h, 1);
        WaitForSingleObject(process.h, INFINITE);
        return std::unexpected(RunError::StartFailed);
    }
    thread.reset();
    return Child{std::move(process), std::move(in_write), std::move(out_read), std::move(job)};
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
    bool contain_children = false;

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
    void kill() noexcept { ::kill(contain_children ? -pid : pid, SIGKILL); }
    bool wait_for_exit_notification() noexcept {
        siginfo_t info{};
        for (;;) {
            if (waitid(P_PID, pid, &info, WEXITED | WNOWAIT) == 0) return info.si_pid == pid;
            if (errno != EINTR) return false;
        }
    }
    std::expected<int, RunError> wait() noexcept {
        int status = 0;
        pid_t result = -1;
        do {
            result = ::waitpid(pid, &status, 0);
        } while (result < 0 && errno == EINTR);
        if (result != pid) {
            return std::unexpected(RunError::Crashed);
        }
        reaped = true;
        return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    }
};

std::expected<Child, RunError> spawn(const std::filesystem::path& exe, const std::vector<std::string>& args,
                                    const ChildLaunchOptions& launch, bool contain_children) {
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
    if (posix_spawn_file_actions_init(&actions) != 0) return std::unexpected(RunError::StartFailed);
    struct FileActionsGuard {
        posix_spawn_file_actions_t& actions;
        ~FileActionsGuard() { posix_spawn_file_actions_destroy(&actions); }
    } actions_guard{actions};
    if (posix_spawn_file_actions_adddup2(&actions, in_read.fd, 0) != 0 ||
        posix_spawn_file_actions_adddup2(&actions, out_write.fd, 1) != 0 ||
        posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0) != 0) {
        return std::unexpected(RunError::StartFailed);
    }
    if (contain_children && posix_spawn_file_actions_addclosefrom_np(&actions, 3) != 0) {
        return std::unexpected(RunError::StartFailed);
    }
    if (!launch.working_directory.empty() &&
        posix_spawn_file_actions_addchdir_np(&actions, launch.working_directory.c_str()) != 0) {
        return std::unexpected(RunError::StartFailed);
    }
    const std::string path = exe.string();
    std::vector<char*> argv{const_cast<char*>(path.c_str())};
    for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);
    std::vector<char*> envp;
    if (!launch.inherit_environment) {
        envp.reserve(launch.environment.size() + 1);
        for (const auto& entry : launch.environment) {
            const auto equals = entry.find('=');
            if (equals == std::string::npos || equals == 0 || entry.find('\0') != std::string::npos) {
                return std::unexpected(RunError::StartFailed);
            }
            envp.push_back(const_cast<char*>(entry.c_str()));
        }
        envp.push_back(nullptr);
    }
    posix_spawnattr_t attributes;
    posix_spawnattr_t* attributes_ptr = nullptr;
    if (contain_children) {
        if (posix_spawnattr_init(&attributes) != 0) return std::unexpected(RunError::StartFailed);
        if (posix_spawnattr_setpgroup(&attributes, 0) != 0 ||
            posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP) != 0) {
            posix_spawnattr_destroy(&attributes);
            return std::unexpected(RunError::StartFailed);
        }
        attributes_ptr = &attributes;
    }
    pid_t pid = -1;
    const int rc = posix_spawn(&pid, path.c_str(), &actions, attributes_ptr, argv.data(),
                               launch.inherit_environment ? environ : envp.data());
    if (contain_children) posix_spawnattr_destroy(&attributes);
    if (rc != 0) {
        return std::unexpected(RunError::StartFailed);
    }
    return Child{pid, std::move(in_write), std::move(out_read), false, contain_children};
}
#endif

// 자식을 띄워 file 을 stdin 에 넣고 stdout 전부를 받는다. 시간·출력 상한·취소·0 아닌 종료는 실패.
std::expected<std::string, RunError> run_child(const std::filesystem::path& exe, const std::vector<std::string>& args,
                                               std::span<const std::byte> file, const RunLimits& limits,
                                               std::stop_token stop, const ChildLaunchOptions& launch = {},
                                               bool wait_for_exit = false) {
    if (stop.stop_requested()) return std::unexpected(RunError::Cancelled);
    const auto before_spawn = std::chrono::steady_clock::now();
    auto child = spawn(exe, args, launch, wait_for_exit);
    if (!child) {
        return std::unexpected(child.error());
    }
    const auto deadline = (wait_for_exit ? before_spawn : std::chrono::steady_clock::now()) + limits.time;
    std::mutex mutex;
    std::condition_variable_any changed;
    bool read_done = false;
    bool write_done = false;
    bool write_failed = false;
    bool overflow = false;
    bool process_exited = !wait_for_exit;
    bool process_wait_failed = false;
    std::string output;
    {
        std::jthread process_waiter;
        if (wait_for_exit) {
            process_waiter = std::jthread([&] {
                const bool exited = child->wait_for_exit_notification();
                const std::lock_guard lock(mutex);
                process_exited = true;
                process_wait_failed = !exited;
                changed.notify_all();
            });
        }
        std::jthread writer([&] {
            const bool written = child->write_all(file);
            child->close_in();
            const std::lock_guard lock(mutex);
            write_failed = !written;
            write_done = true;
            changed.notify_all();
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
        const bool finished = changed.wait_until(lock, stop, deadline, [&] {
            return read_done && (!wait_for_exit || (write_done && process_exited));
        });
        const bool stopped = stop.stop_requested();
        if (!finished || overflow || process_wait_failed) {
            child->kill();
        }
        lock.unlock();
        // 스레드는 여기서 합류한다. 죽였으면 파이프가 닫혀 읽기·쓰기가 곧 끝난다.
        reader.join();
        writer.join();
        if (process_waiter.joinable()) process_waiter.join();
        if (wait_for_exit && finished) child->kill();  // 자식이 남긴 하위 프로세스 그룹도 끝낸다.
        const auto code = child->wait();
        if (!finished) {
            return std::unexpected(stopped ? RunError::Cancelled : RunError::Timeout);
        }
        if (overflow) {
            return std::unexpected(RunError::OutputTooLarge);
        }
        if (process_wait_failed || !code) {
            return std::unexpected(RunError::Crashed);
        }
        if (wait_for_exit && write_failed) {
            return std::unexpected(RunError::Crashed);
        }
        if (*code != 0) {
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

std::expected<std::string, RunError> run_process(const std::filesystem::path& exe,
                                                const std::vector<std::string>& args,
                                                std::span<const std::byte> input, const RunLimits& limits,
                                                std::stop_token stop, const ChildLaunchOptions& launch) {
    if (launch.working_directory.empty() || !std::filesystem::is_directory(launch.working_directory)) {
        return std::unexpected(RunError::StartFailed);
    }
    return run_child(exe, args, input, limits, stop, launch, true);
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
