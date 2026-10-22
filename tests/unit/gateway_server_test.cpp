// 서버 골격 시험: 루프백에 실제로 띄우고 TLS 로 붙는다. handler 는 받은 내용을 기록만 한다.
#include "prompt_airlock/gateway/server.hpp"

#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>

#include <atomic>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>

#include "prompt_airlock/core/sha256.hpp"
#include "prompt_airlock/tls/context.hpp"
#include "listen_retry.hpp"
#include "test_cert.hpp"

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace core = prompt_airlock::core;
namespace gw = prompt_airlock::gateway;
using tcp = asio::ip::tcp;

std::string hash_of(std::string_view token) {
    return core::sha256_hex(std::as_bytes(std::span(token.data(), token.size())));
}

struct Reply {
    unsigned status = 0;
    std::string body;
    std::string www_authenticate;
};

class GatewayServer : public ::testing::Test {
protected:
    void SetUp() override {
        cert_ = pa_test::make_test_certificate();
        auto server_tls = prompt_airlock::tls::make_server_context(cert_.certificate_pem, cert_.private_key_pem);
        auto client_tls = prompt_airlock::tls::make_client_context(std::string_view{cert_.certificate_pem});
        ASSERT_TRUE(server_tls && client_tls);
        server_tls_.emplace(std::move(*server_tls));
        client_tls_.emplace(std::move(*client_tls));
        gw::ServerLimits limits;
        limits.body_bytes = 1024;
        limits.io_timeout = std::chrono::seconds(5);
        pa_test::retry_listen([&] { server_.emplace(io_, *server_tls_, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0), auth_,
                        [this](gw::AcceptedRequest request) -> asio::awaitable<gw::JsonResponse> {
                            std::scoped_lock lock(mutex_);
                            ++handled_;
                            last_origin_ = request.origin->name;
                            last_body_ = request.body;
                            co_return gw::JsonResponse{200, R"({"ok":true})"};
                        },
                        limits); });
        server_->start();
        port_ = server_->local_endpoint().port();
        thread_ = std::thread([this] { io_.run(); });
    }

    void TearDown() override {
        if (server_) {
            server_->stop();
        }
        // io 를 강제로 멈추지 않고 남은 연결이 끝나 io.run 이 스스로 돌아오기를 기다린다.
        // 강제로 멈추면 Windows 에서 다음 시험의 listen 이 드물게 WSAEFAULT 로 실패했다(100회 중 6~7회).
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    // 요청 하나를 보내고 응답을 받는다. 연결이나 handshake 가 실패하면 nullopt.
    std::optional<Reply> send(http::request<http::string_body> req, SSL_CTX* tls = nullptr) {
        asio::io_context io;
        std::optional<asio::ssl::context> owned;  // 넘겨받은 SSL_CTX 는 여기서 해제한다
        if (tls != nullptr) {
            owned.emplace(tls);
        }
        asio::ssl::context& ctx = owned ? *owned : *client_tls_;
        beast::ssl_stream<beast::tcp_stream> stream(io, ctx);
        SSL_set_tlsext_host_name(stream.native_handle(), "localhost");
        SSL_set1_host(stream.native_handle(), "localhost");
        beast::error_code ec;
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(5));
        beast::get_lowest_layer(stream).connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), port_), ec);
        if (ec) {
            return std::nullopt;
        }
        stream.handshake(asio::ssl::stream_base::client, ec);
        if (ec) {
            return std::nullopt;
        }
        req.prepare_payload();
        http::write(stream, req, ec);
        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(stream, buffer, res, ec);
        if (ec) {
            return std::nullopt;
        }
        return Reply{res.result_int(), res.body(), std::string(res[http::field::www_authenticate])};
    }

    static http::request<http::string_body> request(std::string token, std::string body = R"({"messages":[]})") {
        http::request<http::string_body> req{http::verb::post, "/v1/chat/completions", 11};
        req.set(http::field::host, "localhost");
        req.set(http::field::content_type, "application/json");
        if (!token.empty()) {
            req.set(http::field::authorization, "Bearer " + token);
        }
        req.body() = std::move(body);
        return req;
    }

    static std::string code_of(const Reply& reply) {
        return nlohmann::json::parse(reply.body)["error"]["code"].get<std::string>();
    }

    int handled() {
        std::scoped_lock lock(mutex_);
        return handled_;
    }

    pa_test::TestCertificate cert_;
    std::optional<asio::ssl::context> server_tls_;
    std::optional<asio::ssl::context> client_tls_;
    gw::Authenticator auth_{{{"open-desk", hash_of("open-token"), core::GradePolicy::OOnly},
                             {"declare-desk", hash_of("declare-token"), core::GradePolicy::Declare}}};
    asio::io_context io_;
    std::optional<gw::Server> server_;
    std::thread thread_;
    std::uint16_t port_ = 0;
    std::mutex mutex_;
    int handled_ = 0;
    std::string last_origin_;
    std::string last_body_;
};

TEST_F(GatewayServer, PassesAuthenticatedRequestToHandler) {
    const auto reply = send(request("open-token"));
    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(reply->status, 200u);
    EXPECT_EQ(handled(), 1);
    std::scoped_lock lock(mutex_);
    EXPECT_EQ(last_origin_, "open-desk");
    EXPECT_EQ(last_body_, R"({"messages":[]})");
}

TEST_F(GatewayServer, RejectsUnauthenticatedAndLocksAfterFailures) {
    const auto missing = send(request(""));
    ASSERT_TRUE(missing.has_value());
    EXPECT_EQ(missing->status, 401u);
    EXPECT_EQ(missing->www_authenticate, "Bearer");
    EXPECT_EQ(code_of(*missing), "unauthorized");
    for (int i = 1; i < gw::Authenticator::max_failures; ++i) {
        EXPECT_EQ(send(request("wrong"))->status, 401u);
    }
    const auto locked = send(request("open-token"));
    ASSERT_TRUE(locked.has_value());
    EXPECT_EQ(locked->status, 429u);
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayServer, RejectsWrongRouteMethodAndMediaType) {
    auto wrong_path = request("open-token");
    wrong_path.target("/v1/completions");
    EXPECT_EQ(send(wrong_path)->status, 404u);
    auto wrong_method = request("open-token", "");
    wrong_method.method(http::verb::get);
    EXPECT_EQ(send(wrong_method)->status, 405u);
    auto wrong_type = request("open-token");
    wrong_type.set(http::field::content_type, "text/plain");
    EXPECT_EQ(send(wrong_type)->status, 415u);
    auto with_charset = request("open-token");
    with_charset.set(http::field::content_type, "application/json; charset=utf-8");
    EXPECT_EQ(send(with_charset)->status, 200u);
    EXPECT_EQ(handled(), 1);
}

TEST_F(GatewayServer, RejectsOversizedBodyWithoutCallingHandler) {
    const auto reply = send(request("open-token", std::string(1025, 'x')));
    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(reply->status, 413u);
    EXPECT_EQ(code_of(*reply), "body_too_large");
    EXPECT_EQ(send(request("open-token", std::string(1024, 'x')))->status, 200u);
    EXPECT_EQ(handled(), 1);
}

TEST_F(GatewayServer, AppliesGradeHeaderBeforeHandler) {
    auto sensitive = request("open-token");
    sensitive.set("X-Prompt-Airlock-Grade", "S");
    const auto s = send(sensitive);
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->status, 403u);
    EXPECT_EQ(code_of(*s), core::reason_code_name(core::ReasonCode::GradeSensitive));
    // declare 출처는 등급 표시가 있어야 한다
    const auto undeclared = send(request("declare-token"));
    ASSERT_TRUE(undeclared.has_value());
    EXPECT_EQ(code_of(*undeclared), core::reason_code_name(core::ReasonCode::GradeUnresolved));
    auto declared = request("declare-token");
    declared.set("X-Prompt-Airlock-Grade", "O");
    EXPECT_EQ(send(declared)->status, 200u);
    EXPECT_EQ(handled(), 1);
}

TEST_F(GatewayServer, ForbiddenCipherCannotConnect) {
    SSL_CTX* chacha = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(chacha, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_ciphersuites(chacha, "TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_cipher_list(chacha, "ECDHE-ECDSA-CHACHA20-POLY1305");
    EXPECT_FALSE(send(request("open-token"), chacha).has_value());
    EXPECT_EQ(handled(), 0);
}

}  // namespace
