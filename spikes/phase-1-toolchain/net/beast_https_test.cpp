// Boost.Beast + OpenSSL 로 loopback HTTPS mock 서버·클라이언트 왕복, 인증서 검증 실패, timeout 을 확인한다.
#include "test_cert.hpp"

#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <chrono>
#include <optional>
#include <string>

namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
namespace beast = boost::beast;
namespace http = boost::beast::http;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

struct ClientResult {
    beast::error_code ec;
    unsigned status = 0;
    std::string body;
};

enum class ServerMode { Respond, Stall };

asio::awaitable<void> serve_one(tcp::acceptor& acceptor, ssl::context& ctx, ServerMode mode) {
    auto socket = co_await acceptor.async_accept(asio::use_awaitable);
    beast::ssl_stream<beast::tcp_stream> stream(std::move(socket), ctx);
    stream.next_layer().expires_after(5s);
    auto [hs_ec] = co_await stream.async_handshake(ssl::stream_base::server, asio::as_tuple(asio::use_awaitable));
    if (hs_ec) co_return;

    beast::flat_buffer buffer;
    http::request<http::string_body> req;
    auto [rd_ec, n] = co_await http::async_read(stream, buffer, req, asio::as_tuple(asio::use_awaitable));
    if (rd_ec) co_return;
    if (mode == ServerMode::Stall) {
        // 응답하지 않고 연결만 유지해 클라이언트 timeout 을 유도한다.
        asio::steady_timer hold(co_await asio::this_coro::executor, 2s);
        co_await hold.async_wait(asio::as_tuple(asio::use_awaitable));
        co_return;
    }
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::content_type, "application/json");
    res.body() = R"({"status":"ok","echo":")" + std::string(req.target()) + R"("})";
    res.prepare_payload();
    co_await http::async_write(stream, res, asio::as_tuple(asio::use_awaitable));
    co_await stream.async_shutdown(asio::as_tuple(asio::use_awaitable));
}

asio::awaitable<ClientResult> fetch(unsigned short port, ssl::context& ctx, std::chrono::milliseconds timeout) {
    ClientResult out;
    auto ex = co_await asio::this_coro::executor;
    beast::ssl_stream<beast::tcp_stream> stream(ex, ctx);
    SSL_set_tlsext_host_name(stream.native_handle(), "localhost");
    stream.set_verify_callback(ssl::host_name_verification("localhost"));

    stream.next_layer().expires_after(timeout);
    auto [c_ec] = co_await stream.next_layer().async_connect(
        tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), asio::as_tuple(asio::use_awaitable));
    if (c_ec) { out.ec = c_ec; co_return out; }
    auto [h_ec] = co_await stream.async_handshake(ssl::stream_base::client, asio::as_tuple(asio::use_awaitable));
    if (h_ec) { out.ec = h_ec; co_return out; }

    http::request<http::empty_body> req{http::verb::get, "/v1/mock", 11};
    req.set(http::field::host, "localhost");
    auto [w_ec, wn] = co_await http::async_write(stream, req, asio::as_tuple(asio::use_awaitable));
    if (w_ec) { out.ec = w_ec; co_return out; }

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    auto [r_ec, rn] = co_await http::async_read(stream, buffer, res, asio::as_tuple(asio::use_awaitable));
    if (r_ec) { out.ec = r_ec; co_return out; }
    out.status = res.result_int();
    out.body = res.body();
    co_return out;
}

struct Fixture {
    pa_spike::TestCert cert;
    ssl::context server_ctx{ssl::context::tls_server};

    Fixture() {
        auto made = pa_spike::make_test_cert();
        if (!made) throw std::runtime_error(made.error());
        cert = std::move(*made);
        server_ctx.set_options(ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1);
        server_ctx.use_certificate_chain(asio::buffer(cert.cert_pem));
        server_ctx.use_private_key(asio::buffer(cert.key_pem), ssl::context::pem);
    }

    ssl::context trusting_client() const {
        ssl::context ctx{ssl::context::tls_client};
        ctx.set_verify_mode(ssl::verify_peer);
        ctx.add_certificate_authority(asio::buffer(cert.cert_pem));
        return ctx;
    }

    ClientResult run(ssl::context& client_ctx, ServerMode mode, std::chrono::milliseconds timeout) {
        asio::io_context io;
        tcp::acceptor acceptor(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
        const auto port = acceptor.local_endpoint().port();
        std::optional<ClientResult> result;
        asio::co_spawn(io, serve_one(acceptor, server_ctx, mode), asio::detached);
        asio::co_spawn(io, fetch(port, client_ctx, timeout), [&](std::exception_ptr, ClientResult r) {
            result = std::move(r);
            acceptor.close();
            io.stop();
        });
        io.run();
        return result.value_or(ClientResult{});
    }
};

}  // namespace

TEST(BeastHttps, RoundTripWithVerifiedCertificate) {
    Fixture f;
    auto client = f.trusting_client();
    const auto r = f.run(client, ServerMode::Respond, 3s);
    ASSERT_FALSE(r.ec) << r.ec.message();
    EXPECT_EQ(r.status, 200u);
    EXPECT_EQ(r.body, R"({"status":"ok","echo":"/v1/mock"})");
}

TEST(BeastHttps, UntrustedCertificateFailsClosed) {
    Fixture f;
    ssl::context untrusting{ssl::context::tls_client};
    untrusting.set_verify_mode(ssl::verify_peer);  // CA 미등록
    const auto r = f.run(untrusting, ServerMode::Respond, 3s);
    EXPECT_TRUE(r.ec);
    EXPECT_EQ(r.status, 0u);
}

TEST(BeastHttps, ReadTimeoutReturnsError) {
    Fixture f;
    auto client = f.trusting_client();
    const auto start = std::chrono::steady_clock::now();
    const auto r = f.run(client, ServerMode::Stall, 200ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_EQ(r.ec, beast::error::timeout) << r.ec.message();
    EXPECT_LT(elapsed, 1500ms);
}
