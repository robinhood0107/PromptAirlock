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
#include <windows.h>
#include <dpapi.h>
#else
#include <sys/stat.h>
#endif

#include <algorithm>
#include <fstream>
#include <iterator>
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
    auto temp = path;
    temp += ".tmp";
    std::error_code ec;
    std::filesystem::remove(temp, ec);
    {
        std::ofstream file(temp, std::ios::binary | std::ios::trunc);
        // 내용을 쓰기 전에 소유자만 읽고 쓰게 한다(Linux 는 이 권한이어야 load_credential 이 읽는다).
        std::filesystem::permissions(temp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace, ec);
        if (!file || ec) {
            return std::unexpected(CredentialError::Unreadable);
        }
        file << *sealed;
        if (!file.flush()) {
            return std::unexpected(CredentialError::Unreadable);
        }
    }
    std::filesystem::rename(temp, path, ec);
    if (ec) {
        std::filesystem::remove(temp, ec);
        return std::unexpected(CredentialError::Unreadable);
    }
    return {};
}

HttpsClient::HttpsClient(asio::ssl::context& tls, Endpoint endpoint, std::filesystem::path credential_file,
                         ClientLimits limits)
    : tls_(tls), endpoint_(std::move(endpoint)), credential_file_(std::move(credential_file)), limits_(limits) {}

asio::awaitable<Result> HttpsClient::send(std::string body) const {
    // 보내기 직전에 읽어 바꿔 끼운 자격 증명을 쓴다. 읽지 못하면 연결도 하지 않는다(실패하면 막는 쪽).
    const auto credential = load_credential(credential_file_);
    if (!credential) {
        co_return std::unexpected(gateway::ProviderError::Unavailable);
    }
    const auto executor = co_await asio::this_coro::executor;
    tcp::resolver resolver(executor);
    auto [resolve_error, results] =
        co_await resolver.async_resolve(endpoint_.host, std::to_string(endpoint_.port), use_tuple);
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

    if (auto [ec, connected] = co_await beast::get_lowest_layer(stream).async_connect(results, use_tuple); ec) {
        co_return std::unexpected(classify(ec));
    }
    if (auto [ec] = co_await stream.async_handshake(asio::ssl::stream_base::client, use_tuple); ec) {
        co_return std::unexpected(classify(ec));
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
    if (auto [ec, written] = co_await http::async_write(stream, req, use_tuple); ec) {
        co_return std::unexpected(classify(ec));
    }

    beast::flat_buffer buffer;
    http::response_parser<http::string_body> parser;
    parser.body_limit(limits_.response_bytes);
    if (auto [ec, read] = co_await http::async_read(stream, buffer, parser, use_tuple); ec) {
        co_return std::unexpected(ec == http::error::body_limit ? gateway::ProviderError::BadResponse : classify(ec));
    }
    auto& res = parser.get();
    gateway::ProviderReply reply{res.result_int(), std::move(res.body())};
    (void)co_await stream.async_shutdown(use_tuple);  // 응답은 이미 받았으므로 닫기 실패는 무시한다
    co_return reply;
}

}  // namespace prompt_airlock::provider
