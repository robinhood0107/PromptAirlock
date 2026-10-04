// transport 별 ByteStream 구현(Boost.Asio). 연결마다 io_context 하나를 두고 run_for 로 timeout 을 건다.
// Asio 예외는 이 파일 경계에서 Result 로 바꾼다.
#include "prompt_airlock/vault/stream.hpp"

#include <charconv>
#include <optional>
#include <string>
#include <system_error>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#ifdef _WIN32
#include <windows.h>

#include <boost/asio/windows/stream_handle.hpp>
#else
#include <sys/socket.h>
#include <unistd.h>

#include <boost/asio/local/stream_protocol.hpp>
#endif

namespace asio = boost::asio;

namespace prompt_airlock::vault {
namespace {

using std::chrono::milliseconds;

ErrorCode map_error(const boost::system::error_code& ec) {
    if (ec == asio::error::eof || ec == asio::error::connection_reset || ec == asio::error::broken_pipe ||
        ec == asio::error::connection_aborted || ec == asio::error::not_connected) {
        return ErrorCode::Disconnected;
    }
#ifdef _WIN32
    if (ec.category() == boost::system::system_category()) {
        switch (ec.value()) {
            case ERROR_BROKEN_PIPE:
            case ERROR_PIPE_NOT_CONNECTED:
            case ERROR_NO_DATA:
            case ERROR_NETNAME_DELETED:
                return ErrorCode::Disconnected;
            default:
                break;
        }
    }
#endif
    return ErrorCode::Io;
}

// 비동기 연산 하나를 timeout 안에 끝낸다. 끝나지 않으면 취소하고 handler 를 회수한 뒤 Timeout.
template <class Stream, class Start>
std::optional<boost::system::error_code> run_with_timeout(asio::io_context& ctx, Stream& s, Start start,
                                                           milliseconds timeout) {
    std::optional<boost::system::error_code> result;
    start([&result](const boost::system::error_code& ec, auto&&...) { result = ec; });
    ctx.restart();
    ctx.run_for(timeout);
    if (!result) {
        boost::system::error_code ignored;
        s.cancel(ignored);
        ctx.restart();
        ctx.run();
        return std::nullopt;
    }
    return result;
}

template <class Stream>
class AsioStream final : public ByteStream {
public:
    AsioStream(std::unique_ptr<asio::io_context> ctx, Stream s) : ctx_(std::move(ctx)), s_(std::move(s)) {}
    ~AsioStream() override { close(); }

    Result<void> write_all(std::span<const std::uint8_t> data, milliseconds timeout) override {
        return run([&](auto h) { asio::async_write(s_, asio::buffer(data.data(), data.size()), h); }, timeout);
    }

    Result<void> read_exact(std::span<std::uint8_t> out, milliseconds timeout) override {
        return run([&](auto h) { asio::async_read(s_, asio::buffer(out.data(), out.size()), h); }, timeout);
    }

    void close() noexcept override {
        boost::system::error_code ignored;
        s_.close(ignored);
    }

private:
    template <class Start>
    Result<void> run(Start start, milliseconds timeout) {
        if (!s_.is_open()) {
            return fail(ErrorCode::Disconnected);
        }
        try {
            auto r = run_with_timeout(*ctx_, s_, start, timeout);
            if (!r) {
                close();
                return fail(ErrorCode::Timeout);
            }
            if (*r) {
                close();
                return fail(map_error(*r));
            }
            return {};
        } catch (...) {
            close();
            return fail(ErrorCode::Io);
        }
    }

    // stream 보다 먼저 선언해 나중에 파괴되게 한다.
    std::unique_ptr<asio::io_context> ctx_;
    Stream s_;
};

Result<std::unique_ptr<ByteStream>> open_tcp(const std::string& addr, const StreamOptions& opts) {
    // 루프백 주소만 허용한다.
    constexpr std::string_view prefix = "127.0.0.1:";
    if (!addr.starts_with(prefix)) {
        return fail(ErrorCode::ConnectFailed);
    }
    unsigned short port = 0;
    const char* b = addr.data() + prefix.size();
    const char* e = addr.data() + addr.size();
    if (auto [p, ec] = std::from_chars(b, e, port); ec != std::errc{} || p != e || port == 0) {
        return fail(ErrorCode::ConnectFailed);
    }
    auto ctx = std::make_unique<asio::io_context>(1);
    asio::ip::tcp::socket sock(*ctx);
    const asio::ip::tcp::endpoint ep(asio::ip::make_address_v4("127.0.0.1"), port);
    auto r = run_with_timeout(*ctx, sock, [&](auto h) { sock.async_connect(ep, h); }, opts.connect_timeout);
    if (!r || *r) {
        return fail(ErrorCode::ConnectFailed);
    }
    sock.set_option(asio::ip::tcp::no_delay(true));
    return std::make_unique<AsioStream<asio::ip::tcp::socket>>(std::move(ctx), std::move(sock));
}

#ifdef _WIN32
std::wstring widen(const std::string& s) {
    if (s.empty()) {
        return {};
    }
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n > 0 ? n : 0), L'\0');
    if (n > 0) {
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), w.data(), n);
    }
    return w;
}

Result<std::unique_ptr<ByteStream>> open_pipe(const std::string& name, const StreamOptions& opts) {
    const std::wstring wname = widen(name);
    if (wname.empty() || !wname.starts_with(LR"(\\.\pipe\)")) {
        return fail(ErrorCode::ConnectFailed);
    }
    const auto deadline = std::chrono::steady_clock::now() + opts.connect_timeout;
    HANDLE h = INVALID_HANDLE_VALUE;
    for (;;) {
        // SECURITY_IDENTIFICATION: 서버가 이 클라이언트 토큰으로 대리 실행(impersonate)하지 못하게 한다.
        h = CreateFileW(wname.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            break;
        }
        if (GetLastError() != ERROR_PIPE_BUSY) {
            return fail(ErrorCode::ConnectFailed);
        }
        const auto left = std::chrono::duration_cast<milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0 || !WaitNamedPipeW(wname.c_str(), static_cast<DWORD>(left.count()))) {
            return fail(ErrorCode::ConnectFailed);
        }
    }
    if (opts.expected_server_pid) {
        ULONG pid = 0;
        if (!GetNamedPipeServerProcessId(h, &pid) || pid != *opts.expected_server_pid) {
            CloseHandle(h);
            return fail(ErrorCode::ServerIdentityMismatch);
        }
    }
    auto ctx = std::make_unique<asio::io_context>(1);
    try {
        asio::windows::stream_handle sh(*ctx, h);
        return std::make_unique<AsioStream<asio::windows::stream_handle>>(std::move(ctx), std::move(sh));
    } catch (...) {
        // stream_handle 생성자가 실패하면 소유권을 넘겨받지 못한 상태다.
        CloseHandle(h);
        return fail(ErrorCode::Io);
    }
}
#else
Result<std::unique_ptr<ByteStream>> open_uds(const std::string& path, const StreamOptions& opts) {
    using asio::local::stream_protocol;
    auto ctx = std::make_unique<asio::io_context>(1);
    stream_protocol::socket sock(*ctx);
    const stream_protocol::endpoint ep(path);
    auto r = run_with_timeout(*ctx, sock, [&](auto h) { sock.async_connect(ep, h); }, opts.connect_timeout);
    if (!r || *r) {
        return fail(ErrorCode::ConnectFailed);
    }
    // 서버 프로세스 신원과 uid 를 커널이 기록한 값으로 확인한다.
    ucred cred{};
    socklen_t len = sizeof(cred);
    if (getsockopt(sock.native_handle(), SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0 || cred.uid != getuid()) {
        return fail(ErrorCode::ServerIdentityMismatch);
    }
    if (opts.expected_server_pid && static_cast<std::uint64_t>(cred.pid) != *opts.expected_server_pid) {
        return fail(ErrorCode::ServerIdentityMismatch);
    }
    return std::make_unique<AsioStream<stream_protocol::socket>>(std::move(ctx), std::move(sock));
}
#endif

}  // namespace

Result<std::unique_ptr<ByteStream>> open_stream(const Endpoint& ep, const StreamOptions& opts) {
    try {
        switch (ep.kind) {
            case TransportKind::Tcp:
                return open_tcp(ep.address, opts);
            case TransportKind::NamedPipe:
#ifdef _WIN32
                return open_pipe(ep.address, opts);
#else
                return fail(ErrorCode::ConnectFailed);
#endif
            case TransportKind::UnixSocket:
#ifdef _WIN32
                return fail(ErrorCode::ConnectFailed);
#else
                return open_uds(ep.address, opts);
#endif
        }
    } catch (...) {
        return fail(ErrorCode::ConnectFailed);
    }
    return fail(ErrorCode::ConnectFailed);
}

}  // namespace prompt_airlock::vault
