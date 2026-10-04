// Vault 프로세스 실행·종료. READY 한 줄을 timeout 안에 읽고 파싱한다(폴링·sleep 없이 대기).
#include "prompt_airlock/vault/process.hpp"

#include <atomic>
#include <cerrno>
#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace prompt_airlock::vault {
namespace {

using std::chrono::milliseconds;

struct ParsedReady {
    Endpoint endpoint;
    std::string secret_hex;
    std::uint64_t pid = 0;
};

// "PA-VAULT-READY v=1 transport=<tcp|pipe|uds> endpoint=<addr> pid=<n> secret=<64 hex>"
std::optional<ParsedReady> parse_ready(std::string_view line) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.remove_suffix(1);
    }
    constexpr std::string_view tag = "PA-VAULT-READY ";
    if (!line.starts_with(tag)) {
        return std::nullopt;
    }
    line.remove_prefix(tag.size());
    ParsedReady out;
    bool have_v = false, have_t = false, have_e = false, have_p = false, have_s = false;
    while (!line.empty()) {
        const auto sp = line.find(' ');
        const std::string_view kv = line.substr(0, sp);
        line = sp == std::string_view::npos ? std::string_view{} : line.substr(sp + 1);
        const auto eq = kv.find('=');
        if (eq == std::string_view::npos) {
            return std::nullopt;
        }
        const auto k = kv.substr(0, eq);
        const auto v = kv.substr(eq + 1);
        if (k == "v") {
            if (v != "1") return std::nullopt;
            have_v = true;
        } else if (k == "transport") {
            if (v == "tcp") out.endpoint.kind = TransportKind::Tcp;
            else if (v == "pipe") out.endpoint.kind = TransportKind::NamedPipe;
            else if (v == "uds") out.endpoint.kind = TransportKind::UnixSocket;
            else return std::nullopt;
            have_t = true;
        } else if (k == "endpoint") {
            out.endpoint.address = std::string(v);
            have_e = !v.empty();
        } else if (k == "pid") {
            auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), out.pid);
            have_p = ec == std::errc{} && p == v.data() + v.size();
        } else if (k == "secret") {
            out.secret_hex = std::string(v);
            have_s = true;
        } else {
            return std::nullopt;
        }
    }
    if (!(have_v && have_t && have_e && have_p && have_s)) {
        secure_wipe(out.secret_hex);
        return std::nullopt;
    }
    return out;
}

Result<ReadyInfo> to_ready(std::string& line) {
    auto parsed = parse_ready(line);
    secure_wipe(line);
    if (!parsed) {
        return fail(ErrorCode::ReadyLineInvalid);
    }
    auto secret = AuthSecret::from_hex(parsed->secret_hex);
    secure_wipe(parsed->secret_hex);
    if (!secret) {
        return std::unexpected(secret.error());
    }
    return ReadyInfo{std::move(parsed->endpoint), std::move(*secret), parsed->pid};
}

constexpr std::size_t kMaxReadyLine = 1024;

}  // namespace

#ifdef _WIN32

namespace {

std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

// Windows 명령줄 인자 규칙에 맞춰 따옴표 처리한다.
void append_quoted(std::wstring& cmd, const std::wstring& arg) {
    if (!arg.empty() && arg.find_first_of(L" \t\"") == std::wstring::npos) {
        cmd += arg;
        return;
    }
    cmd += L'"';
    std::size_t backslashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') {
            ++backslashes;
            continue;
        }
        if (c == L'"') {
            cmd.append(backslashes * 2 + 1, L'\\');
        } else {
            cmd.append(backslashes, L'\\');
        }
        backslashes = 0;
        cmd += c;
    }
    cmd.append(backslashes * 2, L'\\');
    cmd += L'"';
}

struct Handle {
    HANDLE h = nullptr;
    Handle() = default;
    explicit Handle(HANDLE x) : h(x == INVALID_HANDLE_VALUE ? nullptr : x) {}
    Handle(Handle&& o) noexcept : h(std::exchange(o.h, nullptr)) {}
    Handle& operator=(Handle&& o) noexcept {
        reset();
        h = std::exchange(o.h, nullptr);
        return *this;
    }
    ~Handle() { reset(); }
    void reset() noexcept {
        if (h != nullptr) CloseHandle(h);
        h = nullptr;
    }
    explicit operator bool() const noexcept { return h != nullptr; }
};

}  // namespace

struct VaultProcess::Impl {
    Handle process;
    Handle stdin_write;
    std::optional<ReadyInfo> ready;

    ~Impl() { kill(); }

    void kill() noexcept {
        if (process && WaitForSingleObject(process.h, 0) == WAIT_TIMEOUT) {
            TerminateProcess(process.h, 1);
            WaitForSingleObject(process.h, 5000);
        }
        stdin_write.reset();
    }
};

Result<VaultProcess> VaultProcess::spawn(const SpawnOptions& opts) {
    static std::atomic<unsigned> counter{0};
    // stdout: 부모 쪽만 overlapped 인 이름 있는 파이프. 익명 파이프는 timeout 대기를 지원하지 않는다.
    const std::wstring name = L"\\\\.\\pipe\\pa-vault-spawn-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                              std::to_wstring(counter.fetch_add(1)) + L"-" + std::to_wstring(GetTickCount64());
    Handle out_read(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                     PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, nullptr));
    if (!out_read) return fail(ErrorCode::SpawnFailed);
    SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    Handle out_write(CreateFileW(name.c_str(), GENERIC_WRITE, 0, &inherit, OPEN_EXISTING, 0, nullptr));
    if (!out_write) return fail(ErrorCode::SpawnFailed);

    HANDLE in_r = nullptr, in_w = nullptr;
    if (!CreatePipe(&in_r, &in_w, &inherit, 0)) return fail(ErrorCode::SpawnFailed);
    Handle in_read(in_r), in_write(in_w);
    SetHandleInformation(in_write.h, HANDLE_FLAG_INHERIT, 0);

    // 자식 stderr 는 부모 stderr 를 상속 가능한 사본으로 넘긴다. 없으면 NUL.
    Handle err;
    HANDLE parent_err = GetStdHandle(STD_ERROR_HANDLE);
    HANDLE dup = nullptr;
    if (parent_err != nullptr && parent_err != INVALID_HANDLE_VALUE &&
        DuplicateHandle(GetCurrentProcess(), parent_err, GetCurrentProcess(), &dup, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
        err = Handle(dup);
    } else {
        err = Handle(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr));
    }
    if (!err) return fail(ErrorCode::SpawnFailed);

    // 상속 핸들을 이 세 개로 제한한다. 동시에 여러 자식을 띄워도 서로의 stdin 을 물려받지 않는다.
    HANDLE inherit_list[3] = {in_read.h, out_write.h, err.h};
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    std::vector<std::byte> attr_buf(attr_size);
    auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)) return fail(ErrorCode::SpawnFailed);
    struct AttrGuard {
        LPPROC_THREAD_ATTRIBUTE_LIST a;
        ~AttrGuard() { DeleteProcThreadAttributeList(a); }
    } attr_guard{attrs};
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit_list, sizeof(inherit_list), nullptr,
                                   nullptr)) {
        return fail(ErrorCode::SpawnFailed);
    }

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = in_read.h;
    si.StartupInfo.hStdOutput = out_write.h;
    si.StartupInfo.hStdError = err.h;
    si.lpAttributeList = attrs;

    const std::wstring exe = opts.exe.wstring();
    std::wstring cmd;
    append_quoted(cmd, exe);
    for (const auto& a : opts.args) {
        cmd += L' ';
        append_quoted(cmd, widen(a));
    }
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                        nullptr, nullptr, &si.StartupInfo, &pi)) {
        return fail(ErrorCode::SpawnFailed);
    }
    CloseHandle(pi.hThread);
    auto impl = std::make_unique<Impl>();
    impl->process = Handle(pi.hProcess);
    impl->stdin_write = std::move(in_write);
    // 자식 쪽 끝은 닫아야 자식 종료 시 EOF 를 받는다.
    in_read.reset();
    out_write.reset();
    err.reset();

    // READY 한 줄을 읽는다. 데이터 도착·자식 종료·timeout 중 먼저 오는 것을 기다린다.
    Handle ev(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!ev) return fail(ErrorCode::SpawnFailed);
    const auto deadline = std::chrono::steady_clock::now() + opts.ready_timeout;
    std::string line;
    char buf[256];
    while (line.find('\n') == std::string::npos) {
        if (line.size() > kMaxReadyLine) return fail(ErrorCode::ReadyLineInvalid);
        OVERLAPPED ov{};
        ov.hEvent = ev.h;
        ResetEvent(ev.h);
        DWORD got = 0;
        if (!ReadFile(out_read.h, buf, sizeof(buf), nullptr, &ov) && GetLastError() != ERROR_IO_PENDING) {
            return fail(ErrorCode::SpawnFailed);
        }
        const auto left = std::chrono::duration_cast<milliseconds>(deadline - std::chrono::steady_clock::now());
        HANDLE waits[2] = {ev.h, impl->process.h};
        const DWORD w = WaitForMultipleObjects(2, waits, FALSE, static_cast<DWORD>(left.count() > 0 ? left.count() : 0));
        if (w != WAIT_OBJECT_0) {
            CancelIoEx(out_read.h, &ov);
            GetOverlappedResult(out_read.h, &ov, &got, TRUE);
            return fail(ErrorCode::SpawnFailed);
        }
        if (!GetOverlappedResult(out_read.h, &ov, &got, FALSE) || got == 0) {
            return fail(ErrorCode::SpawnFailed);
        }
        line.append(buf, got);
    }
    SecureZeroMemory(buf, sizeof(buf));
    auto ready = to_ready(line);
    if (!ready) return std::unexpected(ready.error());
    if (ready->pid != GetProcessId(impl->process.h)) return fail(ErrorCode::ReadyLineInvalid);
    impl->ready.emplace(std::move(*ready));
    return VaultProcess(std::move(impl));
}

void VaultProcess::kill() noexcept {
    if (impl_) impl_->kill();
}

void VaultProcess::close_stdin() noexcept {
    if (impl_) impl_->stdin_write.reset();
}

bool VaultProcess::wait_exit(milliseconds timeout) noexcept {
    return impl_ && impl_->process &&
           WaitForSingleObject(impl_->process.h, static_cast<DWORD>(timeout.count())) == WAIT_OBJECT_0;
}

#else  // POSIX

namespace {

struct Fd {
    int fd = -1;
    Fd() = default;
    explicit Fd(int x) : fd(x) {}
    Fd(Fd&& o) noexcept : fd(std::exchange(o.fd, -1)) {}
    Fd& operator=(Fd&& o) noexcept {
        reset();
        fd = std::exchange(o.fd, -1);
        return *this;
    }
    ~Fd() { reset(); }
    void reset() noexcept {
        if (fd >= 0) ::close(fd);
        fd = -1;
    }
};

}  // namespace

struct VaultProcess::Impl {
    pid_t pid = -1;
    Fd pidfd;
    Fd stdin_write;
    bool reaped = false;
    std::optional<ReadyInfo> ready;

    ~Impl() { kill(); }

    void reap_blocking() noexcept {
        if (pid > 0 && !reaped) {
            int st = 0;
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
            }
            reaped = true;
        }
    }

    void kill() noexcept {
        if (pid > 0 && !reaped) {
            ::kill(pid, SIGKILL);
            reap_blocking();
        }
        stdin_write.reset();
    }
};

Result<VaultProcess> VaultProcess::spawn(const SpawnOptions& opts) {
    int in[2], out[2];
    if (pipe2(in, O_CLOEXEC) != 0) return fail(ErrorCode::SpawnFailed);
    Fd in_r(in[0]), in_w(in[1]);
    if (pipe2(out, O_CLOEXEC) != 0) return fail(ErrorCode::SpawnFailed);
    Fd out_r(out[0]), out_w(out[1]);

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    struct FaGuard {
        posix_spawn_file_actions_t* f;
        ~FaGuard() { posix_spawn_file_actions_destroy(f); }
    } fa_guard{&fa};
    // dup2 대상(0, 1)은 CLOEXEC 가 풀린다. 나머지 파이프 끝은 CLOEXEC 로 자식에 남지 않는다.
    posix_spawn_file_actions_adddup2(&fa, in_r.fd, 0);
    posix_spawn_file_actions_adddup2(&fa, out_w.fd, 1);

    const std::string exe = opts.exe.string();
    std::vector<std::string> args_store;
    args_store.push_back(exe);
    args_store.insert(args_store.end(), opts.args.begin(), opts.args.end());
    std::vector<char*> argv;
    for (auto& a : args_store) argv.push_back(a.data());
    argv.push_back(nullptr);

    pid_t pid = -1;
    if (posix_spawn(&pid, exe.c_str(), &fa, nullptr, argv.data(), environ) != 0) {
        return fail(ErrorCode::SpawnFailed);
    }
    auto impl = std::make_unique<Impl>();
    impl->pid = pid;
    impl->stdin_write = std::move(in_w);
    in_r.reset();
    out_w.reset();
    // pidfd 로 종료를 poll 할 수 있다(Linux 5.3+). 없으면 종료 대기는 SIGKILL 후 blocking wait 로만 한다.
    impl->pidfd = Fd(static_cast<int>(syscall(SYS_pidfd_open, pid, 0)));

    const auto deadline = std::chrono::steady_clock::now() + opts.ready_timeout;
    std::string line;
    char buf[256];
    while (line.find('\n') == std::string::npos) {
        if (line.size() > kMaxReadyLine) return fail(ErrorCode::ReadyLineInvalid);
        const auto left = std::chrono::duration_cast<milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) return fail(ErrorCode::SpawnFailed);
        pollfd p{out_r.fd, POLLIN, 0};
        const int pr = poll(&p, 1, static_cast<int>(left.count()));
        if (pr < 0 && errno == EINTR) continue;
        if (pr <= 0) return fail(ErrorCode::SpawnFailed);
        const ssize_t n = ::read(out_r.fd, buf, sizeof(buf));
        if (n <= 0) return fail(ErrorCode::SpawnFailed);
        line.append(buf, static_cast<std::size_t>(n));
    }
    secure_wipe(buf, sizeof(buf));
    auto ready = to_ready(line);
    if (!ready) return std::unexpected(ready.error());
    if (ready->pid != static_cast<std::uint64_t>(pid)) return fail(ErrorCode::ReadyLineInvalid);
    impl->ready.emplace(std::move(*ready));
    return VaultProcess(std::move(impl));
}

void VaultProcess::kill() noexcept {
    if (impl_) impl_->kill();
}

void VaultProcess::close_stdin() noexcept {
    if (impl_) impl_->stdin_write.reset();
}

bool VaultProcess::wait_exit(milliseconds timeout) noexcept {
    if (!impl_ || impl_->pid <= 0) return false;
    if (impl_->reaped) return true;
    if (impl_->pidfd.fd < 0) return false;
    pollfd p{impl_->pidfd.fd, POLLIN, 0};
    if (poll(&p, 1, static_cast<int>(timeout.count())) <= 0) return false;
    impl_->reap_blocking();
    return true;
}

#endif

VaultProcess::VaultProcess(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
VaultProcess::VaultProcess(VaultProcess&&) noexcept = default;
VaultProcess& VaultProcess::operator=(VaultProcess&&) noexcept = default;
VaultProcess::~VaultProcess() = default;

const ReadyInfo& VaultProcess::ready() const noexcept { return *impl_->ready; }

}  // namespace prompt_airlock::vault
