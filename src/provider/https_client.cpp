#include "prompt_airlock/provider/https_client.hpp"

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <share.h>
#include <sys/stat.h>
#include <windows.h>
#include <dpapi.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <string_view>
#include <utility>

namespace prompt_airlock::provider {
namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
using Result = std::expected<gateway::ProviderReply, gateway::ProviderError>;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);
std::atomic<std::uint64_t> credential_temp_sequence{0};

// 측정값의 수명은 send를 기다리는 호출자에게 있다. 오류로 먼저 돌아가도 총 시간을 남긴다.
struct ClientTimer {
    ClientTimings* output;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point previous = start;

    explicit ClientTimer(ClientTimings* timings) : output(timings) {
        if (output) *output = {};
    }
    ~ClientTimer() {
        if (output) output->total = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start);
    }
    void mark(ClientPhase phase) {
        if (!output) return;
        const auto now = std::chrono::steady_clock::now();
        output->phases[static_cast<std::size_t>(phase)] =
            std::chrono::duration_cast<std::chrono::microseconds>(now - previous);
        output->last = phase;
        previous = now;
    }
};

gateway::ProviderError classify(const beast::error_code& ec) {
    return ec == beast::error::timeout ? gateway::ProviderError::Timeout : gateway::ProviderError::Unavailable;
}

}  // namespace

std::expected<core::SensitiveText, CredentialError> load_credential(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::unexpected(CredentialError::Unreadable);
    }
    std::string value((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
#ifdef _WIN32
    DATA_BLOB sealed{static_cast<DWORD>(value.size()), reinterpret_cast<BYTE*>(value.data())};
    DATA_BLOB opened{};
    if (CryptUnprotectData(&sealed, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &opened) == FALSE) {
        return std::unexpected(CredentialError::NotProtected);
    }
    std::string plain(reinterpret_cast<const char*>(opened.pbData), opened.cbData);
    SecureZeroMemory(opened.pbData, opened.cbData);
    LocalFree(opened.pbData);
    core::SensitiveText owned(std::move(plain));  // 푼 값을 넘겨 지우게 한다
#else
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0 || (st.st_mode & 077) != 0) {
        core::SensitiveText discard(std::move(value));
        return std::unexpected(CredentialError::NotProtected);
    }
    core::SensitiveText owned(std::move(value));  // 읽은 버퍼를 넘겨 지우게 한다
#endif
    std::string_view text = owned.view();
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.remove_suffix(1);
    }
    if (text.empty()) {
        return std::unexpected(CredentialError::Empty);
    }
    if (!std::ranges::all_of(text, [](char c) { return c > 0x20 && c < 0x7f; })) {
        return std::unexpected(CredentialError::InvalidCharacter);
    }
    return core::SensitiveText::copy_of(text);
}

std::expected<std::string, CredentialError> protect_credential(std::string_view plain) {
#ifdef _WIN32
    DATA_BLOB in{static_cast<DWORD>(plain.size()), reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()))};
    DATA_BLOB out{};
    if (CryptProtectData(&in, L"prompt-airlock provider credential", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN,
                         &out) == FALSE) {
        return std::unexpected(CredentialError::NotProtected);
    }
    std::string sealed(reinterpret_cast<const char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    return sealed;
#else
    return std::string(plain);
#endif
}

std::expected<void, CredentialError> store_credential(const std::filesystem::path& path, std::string_view plain) {
    auto sealed = protect_credential(plain);
    if (!sealed) {
        return std::unexpected(sealed.error());
    }
    core::SensitiveText protected_credential(std::move(*sealed));
    const auto process =
#ifdef _WIN32
        static_cast<std::uint64_t>(GetCurrentProcessId());
#else
        static_cast<std::uint64_t>(::getpid());
#endif
    std::filesystem::path temp;
    int descriptor = -1;
    for (unsigned attempt = 0; attempt < 32 && descriptor < 0; ++attempt) {
        temp = path;
        temp += ".tmp." + std::to_string(process) + "." +
                std::to_string(credential_temp_sequence.fetch_add(1, std::memory_order_relaxed));
#ifdef _WIN32
        const int open_result = _wsopen_s(&descriptor, temp.c_str(), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                                          _SH_DENYNO, _S_IREAD | _S_IWRITE);
        if (open_result != 0) {
            errno = open_result;
            descriptor = -1;
        }
#else
        int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        descriptor = ::open(temp.c_str(), flags, 0600);
#endif
        if (descriptor < 0 && errno != EEXIST) {
            return std::unexpected(CredentialError::Unreadable);
        }
    }
    if (descriptor < 0) {
        return std::unexpected(CredentialError::Unreadable);
    }
    std::error_code ec;
    bool written = true;
#ifndef _WIN32
    written = ::fchmod(descriptor, 0600) == 0;
#endif
    std::size_t offset = 0;
    while (written && offset < protected_credential.size()) {
        const auto remaining = protected_credential.size() - offset;
#ifdef _WIN32
        const auto chunk = remaining > std::numeric_limits<unsigned int>::max()
            ? std::numeric_limits<unsigned int>::max() : static_cast<unsigned int>(remaining);
        const int count = _write(descriptor, protected_credential.view().data() + offset, chunk);
#else
        const auto count = ::write(descriptor, protected_credential.view().data() + offset, remaining);
#endif
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            written = false;
            break;
        }
        offset += static_cast<std::size_t>(count);
    }
    if (written) {
#ifdef _WIN32
        written = _commit(descriptor) == 0;
#else
        written = ::fsync(descriptor) == 0;
#endif
    }
#ifdef _WIN32
    const int close_result = _close(descriptor);
#else
    const int close_result = ::close(descriptor);
#endif
    written = written && close_result == 0;
    if (!written) {
        std::filesystem::remove(temp, ec);
        return std::unexpected(CredentialError::Unreadable);
    }
    std::filesystem::rename(temp, path, ec);
    if (ec) {
        std::error_code cleanup_error;
        std::filesystem::remove(temp, cleanup_error);
        return std::unexpected(CredentialError::ReplaceFailed);
    }
    return {};
}

HttpsClient::HttpsClient(asio::ssl::context& tls, Endpoint endpoint, std::filesystem::path credential_file,
                         ClientLimits limits)
    : tls_(tls), endpoint_(std::move(endpoint)), credential_file_(std::move(credential_file)), limits_(limits) {}

asio::awaitable<Result> HttpsClient::send(std::string body, ClientTimings* timings) const {
    ClientTimer timer(timings);
    // 보내기 직전에 읽어 바꿔 끼운 자격 증명을 쓴다. 읽지 못하면 연결도 하지 않는다(실패하면 막는 쪽).
    const auto credential = load_credential(credential_file_);
    timer.mark(ClientPhase::Credential);
    if (!credential) {
        co_return std::unexpected(gateway::ProviderError::Unavailable);
    }
    const auto executor = co_await asio::this_coro::executor;
    tcp::resolver resolver(executor);
    auto [resolve_error, results] =
        co_await resolver.async_resolve(endpoint_.host, std::to_string(endpoint_.port), use_tuple);
    timer.mark(ClientPhase::Resolve);
    if (resolve_error) {
        co_return std::unexpected(gateway::ProviderError::Unavailable);
    }

    beast::ssl_stream<beast::tcp_stream> stream(executor, tls_);
    beast::get_lowest_layer(stream).expires_after(limits_.timeout);  // 연결부터 응답 끝까지 한 번의 상한
    // 상대 인증서의 이름 확인. IP 주소면 SAN 의 IP 를, 아니면 DNS 이름을 맞춰 보고 SNI 를 보낸다.
    boost::system::error_code not_ip;
    (void)asio::ip::make_address(endpoint_.host, not_ip);
    SSL* ssl = stream.native_handle();
    const bool name_set =
        not_ip ? SSL_set_tlsext_host_name(ssl, endpoint_.host.c_str()) == 1 && SSL_set1_host(ssl, endpoint_.host.c_str()) == 1
               : X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), endpoint_.host.c_str()) == 1;
    if (!name_set) {
        co_return std::unexpected(gateway::ProviderError::Unavailable);
    }

    auto [connect_error, connected] = co_await beast::get_lowest_layer(stream).async_connect(results, use_tuple);
    timer.mark(ClientPhase::Connect);
    if (connect_error) {
        co_return std::unexpected(classify(connect_error));
    }
    auto [handshake_error] = co_await stream.async_handshake(asio::ssl::stream_base::client, use_tuple);
    timer.mark(ClientPhase::Handshake);
    if (handshake_error) {
        co_return std::unexpected(classify(handshake_error));
    }

    http::request<http::string_body> req{http::verb::post, endpoint_.target, 11};
    req.set(http::field::host, endpoint_.host);
    req.set(http::field::content_type, "application/json");
    req.set(http::field::accept, "application/json");
    req.set(http::field::user_agent, "prompt-airlock");
    req.set(http::field::authorization, std::string("Bearer ") + std::string(credential->view()));
    req.keep_alive(false);
    req.body() = std::move(body);
    req.prepare_payload();
    auto [write_error, written] = co_await http::async_write(stream, req, use_tuple);
    timer.mark(ClientPhase::Write);
    if (write_error) {
        co_return std::unexpected(classify(write_error));
    }

    beast::flat_buffer buffer;
    http::response_parser<http::string_body> parser;
    parser.body_limit(limits_.response_bytes);
    auto [header_error, header_bytes] = co_await http::async_read_header(stream, buffer, parser, use_tuple);
    timer.mark(ClientPhase::Headers);
    if (header_error) {
        co_return std::unexpected(header_error == http::error::body_limit ? gateway::ProviderError::BadResponse
                                                                        : classify(header_error));
    }
    if (!parser.is_done()) {
        auto [body_error, body_bytes] = co_await http::async_read(stream, buffer, parser, use_tuple);
        timer.mark(ClientPhase::Body);
        if (body_error) {
            co_return std::unexpected(body_error == http::error::body_limit ? gateway::ProviderError::BadResponse
                                                                          : classify(body_error));
        }
    }
    auto& res = parser.get();
    gateway::ProviderReply reply{res.result_int(), std::move(res.body())};
    (void)co_await stream.async_shutdown(use_tuple);  // 응답은 이미 받았으므로 닫기 실패는 무시한다
    timer.mark(ClientPhase::Shutdown);
    co_return reply;
}

}  // namespace prompt_airlock::provider
