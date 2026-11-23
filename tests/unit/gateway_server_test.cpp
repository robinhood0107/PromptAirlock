// 서버 골격 시험: 루프백에 실제로 띄우고 TLS 로 붙는다. handler 는 받은 내용을 기록만 한다.
#include "prompt_airlock/gateway/server.hpp"
#include "prompt_airlock/gateway/confirm.hpp"
#include "prompt_airlock/gateway/response_json.hpp"
#include "prompt_airlock/provider/https_client.hpp"

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <filesystem>
#include <fstream>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "prompt_airlock/core/sha256.hpp"
#include "prompt_airlock/tls/context.hpp"
#include "socket_retry.hpp"
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
    bool keep_alive = false;
    std::string content_type;
    std::string csp;
    std::string referrer;
    std::string nosniff;
};

class GatewayServer : public ::testing::Test {
protected:
    virtual std::size_t body_limit() const { return 1024; }
    virtual bool compatibility() const { return false; }
    virtual std::string credential_rotation_origin() const { return {}; }
    virtual gw::CredentialRotationWriter credential_rotation_writer() { return {}; }
    virtual std::string admin_history_origin() const { return {}; }
    virtual prompt_airlock::audit::AuditLog* audit_log() { return nullptr; }
    void SetUp() override {
        cert_ = pa_test::make_test_certificate();
        auto server_tls = prompt_airlock::tls::make_server_context(cert_.certificate_pem, cert_.private_key_pem);
        auto client_tls = prompt_airlock::tls::make_client_context(std::string_view{cert_.certificate_pem});
        ASSERT_TRUE(server_tls && client_tls);
        server_tls_.emplace(std::move(*server_tls));
        client_tls_.emplace(std::move(*client_tls));
        gw::ServerLimits limits;
        limits.body_bytes = body_limit();
        limits.io_timeout = std::chrono::seconds(5);
        pa_test::retry_listen([&] { server_.emplace(io_, *server_tls_, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0), auth_,
                        [this](gw::AcceptedRequest request) -> asio::awaitable<gw::JsonResponse> {
                            {
                                std::scoped_lock lock(mutex_);
                                ++handled_;
                                last_origin_ = request.origin->name;
                                last_body_ = request.body;
                                last_purpose_ = request.purpose;
                                if (retain_uploads_) uploads_.push_back(request.upload);
                            }
                            changed_.notify_all();
                            if (hold_) {
                                // 오래 걸리는 처리. 취소되면 바로 돌아온다.
                                asio::steady_timer slow(co_await asio::this_coro::executor, std::chrono::seconds(10));
                                const auto [ec] = co_await slow.async_wait(asio::as_tuple(asio::use_awaitable));
                                {
                                    std::scoped_lock lock(mutex_);
                                    cancelled_ = ec == asio::error::operation_aborted;
                                }
                                changed_.notify_all();
                            }
                            std::scoped_lock lock(mutex_);
                            co_return response_.value_or(gw::JsonResponse{200, R"({"ok":true})"});
                        }, limits, audit_log(), compatibility(), credential_rotation_origin(),
                        credential_rotation_writer(), admin_history_origin()); });
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
    std::optional<Reply> send(http::request<http::string_body> req, SSL_CTX* tls = nullptr, bool chunked = false,
                              std::string local_address = {}) {
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
        auto& lowest = beast::get_lowest_layer(stream);
        const tcp::endpoint remote(asio::ip::make_address("127.0.0.1"), port_);
        if (local_address.empty()) {
            ec = pa_test::retry_connect(lowest, remote);
        } else {
            pa_test::SocketRetry retry;
            do {
                lowest.close();
                lowest.socket().open(tcp::v4(), ec);
                if (!ec) lowest.socket().bind(tcp::endpoint(asio::ip::make_address(local_address), 0), ec);
                if (!ec) lowest.connect(remote, ec);
            } while (pa_test::is_environment_fault(ec) && retry.keep_going());
            if (pa_test::is_environment_fault(ec)) retry.fail(boost::system::system_error(ec, "connect"));
        }
        if (ec) {
            return std::nullopt;
        }
        stream.handshake(asio::ssl::stream_base::client, ec);
        if (ec) {
            return std::nullopt;
        }
        req.prepare_payload();
        if (chunked) {
            req.erase(http::field::content_length);
            req.chunked(true);
        }
        http::write(stream, req, ec);
        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(stream, buffer, res, ec);
        if (ec) {
            return std::nullopt;
        }
        return Reply{res.result_int(), res.body(), std::string(res[http::field::www_authenticate]), res.keep_alive(),
            std::string(res[http::field::content_type]), std::string(res["Content-Security-Policy"]),
            std::string(res["Referrer-Policy"]), std::string(res["X-Content-Type-Options"])};
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
                             {"declare-desk", hash_of("declare-token"), core::GradePolicy::Declare},
                             {"admin-console", hash_of("admin-token"), core::GradePolicy::Declare}}};
    asio::io_context io_;
    std::optional<gw::Server> server_;
    std::thread thread_;
    std::uint16_t port_ = 0;
    std::mutex mutex_;
    std::condition_variable changed_;
    std::atomic<bool> hold_{false};
    bool cancelled_ = false;
    int handled_ = 0;
    std::optional<gw::JsonResponse> response_;
    std::string last_origin_;
    std::string last_body_;
    gw::RequestPurpose last_purpose_ = gw::RequestPurpose::Chat;
    std::atomic<bool> retain_uploads_{false};
    std::vector<std::shared_ptr<gw::UploadLease>> uploads_;
};

class GatewayCredentialRotation : public GatewayServer {
protected:
    std::size_t body_limit() const override { return 8192; }

    void SetUp() override {
        root_ = std::filesystem::temp_directory_path() /
                ("pa-credential-rotation-" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(root_);
        auto audit = prompt_airlock::audit::AuditLog::open(root_ / "audit", std::chrono::days(365));
        ASSERT_TRUE(audit);
        audit_ = std::move(*audit);
        credential_file_ = root_ / "provider.cred";
        ASSERT_TRUE(prompt_airlock::provider::store_credential(credential_file_, "old-credential").has_value());
        GatewayServer::SetUp();
    }

    void TearDown() override {
        GatewayServer::TearDown();
        audit_.reset();
        std::filesystem::remove_all(root_);
    }

    std::string credential_rotation_origin() const override { return "open-desk"; }
    gw::CredentialRotationWriter credential_rotation_writer() override {
        return [this](std::string_view credential) {
            ++store_calls_;
            return prompt_airlock::provider::store_credential(credential_file_, credential).has_value();
        };
    }
    prompt_airlock::audit::AuditLog* audit_log() override { return audit_.get(); }

    http::request<http::string_body> credential_request(std::string token, std::string body) const {
        auto req = request(std::move(token), std::move(body));
        req.target("/v1/provider/credential");
        const auto host = "127.0.0.1:" + std::to_string(port_);
        req.set(http::field::host, host);
        req.set(http::field::origin, "https://" + host);
        return req;
    }

    std::filesystem::path root_;
    std::filesystem::path credential_file_;
    std::unique_ptr<prompt_airlock::audit::AuditLog> audit_;
    std::atomic<int> store_calls_{0};
};

class GatewayAdminHistory : public GatewayServer {
protected:
    void SetUp() override {
        root_ = std::filesystem::temp_directory_path() /
                ("pa-admin-history-" +
                 std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(root_);
        auto audit = prompt_airlock::audit::AuditLog::open(root_ / "audit", std::chrono::days(365));
        ASSERT_TRUE(audit);
        audit_ = std::move(*audit);
        GatewayServer::SetUp();
        for (int i = 0; i < 3; ++i) extra_threads_.emplace_back([this] { io_.run(); });
    }

    void TearDown() override {
        if (server_) server_->stop();
        for (auto& thread : extra_threads_) {
            if (thread.joinable()) thread.join();
        }
        GatewayServer::TearDown();
        audit_.reset();
        std::error_code ignored;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root_, ignored)) {
            std::filesystem::permissions(entry.path(), std::filesystem::perms::owner_all,
                                         std::filesystem::perm_options::add, ignored);
        }
        std::filesystem::remove_all(root_, ignored);
    }

    std::string admin_history_origin() const override { return "admin-console"; }
    std::string credential_rotation_origin() const override { return "open-desk"; }
    gw::CredentialRotationWriter credential_rotation_writer() override {
        return [this](std::string_view) {
            ++credential_write_calls_;
            return true;
        };
    }
    prompt_airlock::audit::AuditLog* audit_log() override { return audit_.get(); }

    http::request<http::string_body> admin_request(std::string token, std::string_view target) const {
        auto req = request(std::move(token), "");
        req.method(http::verb::get);
        req.target(target);
        req.erase(http::field::content_type);
        const auto host = "127.0.0.1:" + std::to_string(port_);
        req.set(http::field::host, host);
        req.set(http::field::origin, "https://" + host);
        return req;
    }

    http::request<http::string_body> approval_list_request(std::string token) const {
        auto req = request(std::move(token), "");
        req.method(http::verb::get);
        req.target("/v1/confirmations/pending");
        req.erase(http::field::content_type);
        req.set("X-Prompt-Airlock-Grade", "O");
        const auto host = "127.0.0.1:" + std::to_string(port_);
        req.set(http::field::host, host);
        req.set(http::field::origin, "https://" + host);
        return req;
    }

    std::filesystem::path root_;
    std::unique_ptr<prompt_airlock::audit::AuditLog> audit_;
    int credential_write_calls_ = 0;
    std::vector<std::thread> extra_threads_;
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

TEST_F(GatewayServer, DefaultConfirmationKeepsIts409Contract) {
    {
        std::scoped_lock lock(mutex_);
        response_ = gw::confirm_response(std::string(32, 'a'), {"CONFIDENTIAL_MARKER"});
    }
    const auto reply = send(request("open-token"));
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 409U);
    EXPECT_EQ(code_of(*reply), "confirmation_required");
    EXPECT_EQ(nlohmann::json::parse(reply->body)["error"]["confirm_token"], std::string(32, 'a'));
}

TEST_F(GatewayServer, AnExplicitEmptyConfirmationHeaderIsRejectedBeforeTheHandler) {
    auto empty = request("open-token");
    empty.set("X-Prompt-Airlock-Confirm", "");
    const auto reply = send(empty);
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 400U);
    EXPECT_EQ(code_of(*reply), "bad_request");
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayServer, ServesOnlyLocalBuiltInConsoleAndApprovalResources) {
    auto page = request("", "");
    page.method(http::verb::get);
    page.target("/console");
    const auto host = "127.0.0.1:" + std::to_string(port_);
    page.set(http::field::host, host);
    const auto start = send(page);
    ASSERT_TRUE(start);
    EXPECT_EQ(start->status, 200U);
    EXPECT_EQ(start->content_type, "text/html; charset=utf-8");
    EXPECT_NE(start->body.find("/console/start.js"), std::string::npos);
    EXPECT_NE(start->body.find("id=\"connection-section\""), std::string::npos);
    EXPECT_NE(start->body.find("id=\"rotation-token\" type=\"password\""), std::string::npos);
    EXPECT_NE(start->body.find("id=\"provider-credential\" type=\"password\""), std::string::npos);
    EXPECT_NE(start->body.find("id=\"gateway-check\" type=\"button\""), std::string::npos);
    EXPECT_NE(start->body.find("제공자 호출"), std::string::npos);
    const auto grade_control = start->body.find("id=\"grade-confirm\"");
    ASSERT_NE(grade_control, std::string::npos);
    const auto grade_control_end = start->body.find('>', grade_control);
    ASSERT_NE(grade_control_end, std::string::npos);
    EXPECT_NE(start->body.substr(grade_control, grade_control_end - grade_control).find("type=\"checkbox\""),
              std::string::npos);
    EXPECT_NE(start->body.substr(grade_control, grade_control_end - grade_control).find("required"), std::string::npos);
    EXPECT_EQ(start->body.substr(grade_control, grade_control_end - grade_control).find("checked"), std::string::npos);
    EXPECT_NE(start->csp.find("script-src 'self'"), std::string::npos);
    EXPECT_NE(start->csp.find("connect-src 'self'"), std::string::npos);
    EXPECT_NE(start->csp.find("frame-ancestors 'none'"), std::string::npos);
    EXPECT_NE(start->csp.find("default-src 'none'"), std::string::npos);
    EXPECT_EQ(start->csp.find("unsafe-inline"), std::string::npos);
    EXPECT_EQ(start->body.find("https://"), std::string::npos);
    EXPECT_EQ(start->referrer, "no-referrer");
    EXPECT_EQ(start->nosniff, "nosniff");
    EXPECT_FALSE(start->keep_alive);
    page.set(http::field::origin, "https://" + host);
    EXPECT_EQ(send(page)->status, 200U);
    page.erase(http::field::origin);

    page.target("/console/confirm?token=" + std::string(32, 'a'));
    const auto html = send(page);
    ASSERT_TRUE(html);
    EXPECT_EQ(html->status, 200U);
    EXPECT_EQ(html->content_type, "text/html; charset=utf-8");
    EXPECT_NE(html->csp.find("script-src 'self'"), std::string::npos);
    EXPECT_NE(html->csp.find("frame-ancestors 'none'"), std::string::npos);
    EXPECT_EQ(html->csp.find("unsafe-inline"), std::string::npos);
    EXPECT_EQ(html->referrer, "no-referrer");
    EXPECT_EQ(html->nosniff, "nosniff");
    EXPECT_EQ(html->body.find(std::string(32, 'a')), std::string::npos);
    EXPECT_FALSE(html->keep_alive);
    const std::vector<std::pair<std::string, std::string>> resources = {
        {"/console/start.js", "text/javascript; charset=utf-8"},
        {"/console/start.css", "text/css; charset=utf-8"},
        {"/console/confirm.js", "text/javascript; charset=utf-8"},
        {"/console/confirm.css", "text/css; charset=utf-8"},
        {"/console/confirm.svg", "image/svg+xml"}
    };
    for (const auto& [path, type] : resources) {
        page.target(path);
        const auto resource = send(page);
        ASSERT_TRUE(resource);
        EXPECT_EQ(resource->status, 200U);
        EXPECT_EQ(resource->content_type, type);
        if (path == "/console/start.js") {
            EXPECT_NE(resource->body.find("/v1/preview"), std::string::npos);
            EXPECT_NE(resource->body.find("/v1/provider/credential"), std::string::npos);
            EXPECT_NE(resource->body.find("/v1/admin/audit/counts"), std::string::npos);
            EXPECT_NE(resource->body.find("/v1/admin/audit/events?page="), std::string::npos);
            EXPECT_NE(resource->body.find("/v1/admin/audit/egress/"), std::string::npos);
            EXPECT_NE(resource->body.find("/v1/confirmations/pending"), std::string::npos);
            EXPECT_NE(resource->body.find("/console/confirm?token="), std::string::npos);
            EXPECT_NE(resource->body.find("/console/start.css"), std::string::npos);
            EXPECT_EQ(resource->body.find("localStorage"), std::string::npos);
            EXPECT_EQ(resource->body.find("sessionStorage"), std::string::npos);
            EXPECT_EQ(resource->body.find("innerHTML"), std::string::npos);
            EXPECT_NE(resource->body.find("Authorization: 'Bearer '"), std::string::npos);
            EXPECT_NE(resource->body.find("/v1/confirmations/pending"), std::string::npos);
            EXPECT_NE(resource->body.find("/console/confirm?token="), std::string::npos);
            EXPECT_NE(resource->body.find("adminToken.value = ''"), std::string::npos);
            EXPECT_NE(resource->body.find("adminController.abort()"), std::string::npos);
            EXPECT_NE(resource->body.find("adminEvents.replaceChildren()"), std::string::npos);
        }
    }
    page.target("/console");
    const auto admin_page = send(page);
    ASSERT_TRUE(admin_page);
    EXPECT_EQ(admin_page->status, 200U);
    EXPECT_NE(admin_page->body.find("id=\"admin-history\""), std::string::npos);
    EXPECT_NE(admin_page->body.find("id=\"admin-open\""), std::string::npos);
    EXPECT_NE(admin_page->body.find("id=\"admin-close\""), std::string::npos);
    EXPECT_NE(admin_page->body.find("id=\"admin-token\" type=\"password\""), std::string::npos);
    EXPECT_NE(admin_page->body.find("admin-events"), std::string::npos);
    EXPECT_NE(admin_page->body.find("id=\"approval-list-panel\""), std::string::npos);
    EXPECT_NE(admin_page->body.find("id=\"approval-origin-token\" type=\"password\""), std::string::npos);
    EXPECT_NE(admin_page->body.find("id=\"approval-open-confirm\""), std::string::npos);
    EXPECT_NE(admin_page->body.find("id=\"approval-list-panel\""), std::string::npos);
    EXPECT_NE(admin_page->body.find("id=\"approval-origin-token\" type=\"password\""), std::string::npos);
    EXPECT_NE(admin_page->body.find("id=\"approval-open-confirm\""), std::string::npos);
    page.target("/console?unexpected=1");
    EXPECT_EQ(send(page)->status, 400U);
    page.target("/console/start.js?unexpected=1");
    EXPECT_EQ(send(page)->status, 400U);
    page.target("/console/confirm?token=" + std::string(32, 'a') + "&extra=1");
    EXPECT_EQ(send(page)->status, 400U);
    page.target("/console");
    page.set(http::field::host, "example.invalid");
    EXPECT_EQ(send(page)->status, 403U);
    page.set(http::field::host, host);
    page.set(http::field::origin, "https://example.invalid");
    EXPECT_EQ(send(page)->status, 403U);
    page.erase(http::field::origin);
    EXPECT_EQ(send(page, nullptr, false, "127.0.0.2")->status, 403U);
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayServer, RoutesAuthenticatedPreviewWithTheSameHttpGuards) {
    auto preview = request("open-token");
    preview.target("/v1/preview");
    const auto reply = send(preview);
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 200U);
    EXPECT_EQ(handled(), 1);
    {
        std::scoped_lock lock(mutex_);
        EXPECT_EQ(last_purpose_, gw::RequestPurpose::Preview);
        EXPECT_EQ(last_body_, preview.body());
    }
    preview.set("X-Prompt-Airlock-Grade", "S");
    EXPECT_EQ(send(preview)->status, 403U);
    preview.erase("X-Prompt-Airlock-Grade");
    preview.method(http::verb::get);
    EXPECT_EQ(send(preview)->status, 405U);
    preview.method(http::verb::post);
    preview.set(http::field::content_type, "text/plain");
    EXPECT_EQ(send(preview)->status, 415U);
    preview.set(http::field::content_type, "application/json");
    preview.erase(http::field::authorization);
    EXPECT_EQ(send(preview)->status, 401U);
    EXPECT_EQ(handled(), 1);
}

TEST_F(GatewayServer, CredentialRotationIsDisabledWithoutAnExplicitOrigin) {
    auto req = request("open-token", R"({"credential":"synthetic-secret"})");
    req.target("/v1/provider/credential");
    const auto host = "127.0.0.1:" + std::to_string(port_);
    req.set(http::field::host, host);
    req.set(http::field::origin, "https://" + host);
    const auto reply = send(req);
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 404u);
    EXPECT_EQ(code_of(*reply), "not_found");
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayServer, AdminHistoryReadIsDisabledByDefault) {
    auto req = request("open-token", "");
    req.method(http::verb::get);
    req.target("/v1/admin/audit/counts");
    const auto host = "127.0.0.1:" + std::to_string(port_);
    req.set(http::field::host, host);
    req.set(http::field::origin, "https://" + host);
    const auto reply = send(req);
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 404U);
    EXPECT_EQ(code_of(*reply), "not_found");
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayAdminHistory, ApprovalListUsesSourceOGradeAndLocalRequestGuards) {
    const auto first = send(approval_list_request("open-token"));
    ASSERT_TRUE(first);
    EXPECT_EQ(first->status, 200U);
    EXPECT_EQ(handled(), 1);
    {
        std::scoped_lock lock(mutex_);
        EXPECT_EQ(last_origin_, "open-desk");
        EXPECT_EQ(last_purpose_, gw::RequestPurpose::ConfirmationList);
        EXPECT_TRUE(last_body_.empty());
    }

    auto no_origin = approval_list_request("open-token");
    no_origin.erase(http::field::origin);
    EXPECT_EQ(send(no_origin)->status, 200U);
    const auto declared_source = send(approval_list_request("declare-token"));
    ASSERT_TRUE(declared_source);
    EXPECT_EQ(declared_source->status, 200U);
    EXPECT_EQ(handled(), 3);

    auto wrong_origin = approval_list_request("open-token");
    wrong_origin.set(http::field::origin, "https://example.invalid");
    EXPECT_EQ(send(wrong_origin)->status, 403U);
    auto duplicate_origin = approval_list_request("open-token");
    duplicate_origin.insert(http::field::origin, "https://127.0.0.1:" + std::to_string(port_));
    EXPECT_EQ(send(duplicate_origin)->status, 403U);
    auto wrong_host = approval_list_request("open-token");
    wrong_host.set(http::field::host, "example.invalid");
    EXPECT_EQ(send(wrong_host)->status, 403U);
    EXPECT_EQ(send(approval_list_request("admin-token"))->status, 404U);
    EXPECT_EQ(send(approval_list_request(""))->status, 401U);

    auto classified = approval_list_request("declare-token");
    classified.set("X-Prompt-Airlock-Grade", "S");
    EXPECT_EQ(send(classified)->status, 403U);
    auto duplicate_auth = approval_list_request("open-token");
    duplicate_auth.insert(http::field::authorization, "Bearer open-token");
    EXPECT_EQ(send(duplicate_auth)->status, 400U);
    auto confirm_header = approval_list_request("open-token");
    confirm_header.set("X-Prompt-Airlock-Confirm", std::string(32, 'a'));
    EXPECT_EQ(send(confirm_header)->status, 400U);
    auto content_type = approval_list_request("open-token");
    content_type.set(http::field::content_type, "application/json");
    EXPECT_EQ(send(content_type)->status, 400U);
    auto body = approval_list_request("open-token");
    body.body() = "synthetic-list-body";
    EXPECT_EQ(send(body)->status, 400U);
    auto remote = approval_list_request("open-token");
    const auto remote_reply = send(remote, nullptr, false, "127.0.0.2");
    ASSERT_TRUE(remote_reply);
    EXPECT_EQ(remote_reply->status, 403U);
    EXPECT_EQ(handled(), 3);
}

TEST_F(GatewayAdminHistory, ReturnsAggregateMetadataAndOnlyPreparedEgressText) {
    constexpr std::string_view request_id = "chatcmpl-pa-0123456789abcdef01234567";
    ASSERT_TRUE(audit_->append("request", "info", {{"request_id", request_id}, {"origin", "open-desk"},
        {"grade", "O"}, {"status", 200}, {"entities", {{"PERSON", 1}}}, {"ms", 3.5}, {"result", "pass"}}));
    ASSERT_TRUE(audit_->append("egress", "info", {{"request_id", request_id},
        {"sent", nlohmann::json{{"model", "demo-alias"}, {"max_tokens", 16},
            {"messages", nlohmann::json::array({{{"role", "user"}, {"content", "SYNTHETIC_TOKENIZED_MARKER"}}})}}}}));
    ASSERT_TRUE(audit_->append("egress_answer", "info", {{"request_id", request_id},
        {"answer", "SYNTHETIC_PROVIDER_RESPONSE_MARKER"}}));

    const auto counts_reply = send(admin_request("admin-token", "/v1/admin/audit/counts"));
    ASSERT_TRUE(counts_reply);
    ASSERT_EQ(counts_reply->status, 200U);
    const auto counts = nlohmann::json::parse(counts_reply->body);
    EXPECT_EQ(counts["status"], "available");
    EXPECT_EQ(counts["complete"], true);
    EXPECT_EQ(counts["counts"]["requests"], 1);
    EXPECT_EQ(counts["counts"]["egress_prepared"], 1);
    EXPECT_EQ(counts["counts"]["provider_response_records"], 1);
    EXPECT_EQ(counts_reply->body.find("SYNTHETIC_TOKENIZED_MARKER"), std::string::npos);
    EXPECT_EQ(counts_reply->body.find("SYNTHETIC_PROVIDER_RESPONSE_MARKER"), std::string::npos);

    const auto events_reply = send(admin_request("admin-token", "/v1/admin/audit/events?page=0"));
    ASSERT_TRUE(events_reply);
    ASSERT_EQ(events_reply->status, 200U);
    const auto events = nlohmann::json::parse(events_reply->body);
    ASSERT_FALSE(events["events"].empty());
    EXPECT_EQ(events_reply->body.find("SYNTHETIC_TOKENIZED_MARKER"), std::string::npos);
    EXPECT_EQ(events_reply->body.find("SYNTHETIC_PROVIDER_RESPONSE_MARKER"), std::string::npos);
    EXPECT_EQ(events_reply->body.find("\"sent\""), std::string::npos);
    EXPECT_EQ(events_reply->body.find("\"answer\""), std::string::npos);
    EXPECT_EQ(events_reply->body.find("\"prev\""), std::string::npos);
    EXPECT_EQ(events_reply->body.find("\"hash\""), std::string::npos);

    const auto detail_reply = send(admin_request("admin-token", "/v1/admin/audit/egress/" + std::string(request_id)));
    ASSERT_TRUE(detail_reply);
    ASSERT_EQ(detail_reply->status, 200U);
    const auto detail = nlohmann::json::parse(detail_reply->body);
    EXPECT_EQ(detail["status"], "prepared");
    EXPECT_EQ(detail["delivery_confirmed"], false);
    EXPECT_NE(detail["request_text"].get<std::string>().find("SYNTHETIC_TOKENIZED_MARKER"), std::string::npos);
    EXPECT_EQ(detail_reply->body.find("SYNTHETIC_PROVIDER_RESPONSE_MARKER"), std::string::npos);
    EXPECT_EQ(detail_reply->body.find("\"prev\""), std::string::npos);
    EXPECT_EQ(detail_reply->body.find("\"hash\""), std::string::npos);
    EXPECT_EQ(handled(), 0);
    ASSERT_TRUE(prompt_airlock::audit::verify(audit_->dir()));
    const auto records = audit_->read_recent();
    ASSERT_TRUE(records);
    int read_events = 0;
    for (const auto& record : records->records) {
        if (record["kind"] == "admin_history_access" && record["result"] == "read") ++read_events;
    }
    EXPECT_EQ(read_events, 3);
}

TEST_F(GatewayAdminHistory, ConfirmationListReadAuditDoesNotCountAsRequestOrApproval) {
    ASSERT_TRUE(audit_->append("confirmation", "info", {{"origin", "open-desk"},
        {"operation", "list"}, {"result", "read"}, {"items", 2}, {"truncated", false}}));
    const auto counts = send(admin_request("admin-token", "/v1/admin/audit/counts"));
    ASSERT_TRUE(counts);
    ASSERT_EQ(counts->status, 200U);
    const auto values = nlohmann::json::parse(counts->body)["counts"];
    EXPECT_EQ(values["requests"], 0);
    EXPECT_EQ(values["confirmations"], 0);

    const auto events = send(admin_request("admin-token", "/v1/admin/audit/events?page=0"));
    ASSERT_TRUE(events);
    const auto metadata = nlohmann::json::parse(events->body)["events"];
    const auto item = std::ranges::find_if(metadata, [](const auto& entry) {
        return entry.value("operation", "") == "list";
    });
    ASSERT_NE(item, metadata.end());
    EXPECT_EQ((*item)["kind"], "confirmation");
    EXPECT_FALSE((*item).contains("body_sha256"));
    EXPECT_FALSE((*item).contains("approval_mark"));
}

TEST_F(GatewayAdminHistory, PartialRecentAuditReturnsOnlyVerifiedSuffixAndMarksUnknownDetail) {
    constexpr std::string_view large_request_id = "chatcmpl-pa-10112233445566778899aabb";
    ASSERT_TRUE(audit_->append("egress", "info", {{"request_id", large_request_id},
        {"sent", std::string(prompt_airlock::audit::recent_query_max_line_bytes + 1, 'x')}}));
    ASSERT_TRUE(audit_->append("request", "info", {{"request_id", "chatcmpl-pa-00112233445566778899aabb"},
        {"origin", "dept-a"}, {"grade", "O"}, {"status", 200}, {"result", "pass"}}));

    const auto counts = send(admin_request("admin-token", "/v1/admin/audit/counts"));
    ASSERT_TRUE(counts);
    ASSERT_EQ(counts->status, 200U);
    const auto count_data = nlohmann::json::parse(counts->body);
    EXPECT_EQ(count_data["status"], "partial");
    EXPECT_EQ(count_data["complete"], false);
    EXPECT_EQ(count_data["verification_scope"], "verified_latest_suffix");
    EXPECT_EQ(count_data["counts"]["requests"], 1);
    EXPECT_EQ(count_data["counts"]["egress_prepared"], 0);

    const auto events = send(admin_request("admin-token", "/v1/admin/audit/events?page=0"));
    ASSERT_TRUE(events);
    ASSERT_EQ(events->status, 200U);
    const auto event_data = nlohmann::json::parse(events->body);
    EXPECT_EQ(event_data["status"], "partial");
    EXPECT_EQ(event_data["complete"], false);
    ASSERT_FALSE(event_data["events"].empty());
    EXPECT_EQ(events->body.find(std::string(prompt_airlock::audit::recent_query_max_line_bytes + 1, 'x')),
              std::string::npos);

    const auto detail = send(admin_request("admin-token", "/v1/admin/audit/egress/" + std::string(large_request_id)));
    ASSERT_TRUE(detail);
    ASSERT_EQ(detail->status, 200U);
    const auto detail_data = nlohmann::json::parse(detail->body);
    EXPECT_EQ(detail_data["status"], "range_limited");
    EXPECT_EQ(detail_data["complete"], false);
    EXPECT_EQ(detail->body.find(std::string(prompt_airlock::audit::recent_query_max_line_bytes + 1, 'x')),
              std::string::npos);
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayAdminHistory, DedicatedAdminTokenCannotUseProtectedRequestOrCredentialRoutes) {
    auto ordinary = admin_request("open-token", "/v1/admin/audit/counts");
    ASSERT_EQ(send(ordinary)->status, 404U);

    auto chat = request("admin-token");
    chat.set("X-Prompt-Airlock-Grade", "O");
    EXPECT_EQ(send(chat)->status, 404U);

    auto preview = request("admin-token");
    preview.target("/v1/preview");
    preview.set("X-Prompt-Airlock-Grade", "O");
    EXPECT_EQ(send(preview)->status, 404U);

    auto rotate = request("admin-token", R"({"credential":"synthetic-admin-key"})");
    rotate.target("/v1/provider/credential");
    rotate.set("X-Prompt-Airlock-Grade", "O");
    const auto host = "127.0.0.1:" + std::to_string(port_);
    rotate.set(http::field::host, host);
    rotate.set(http::field::origin, "https://" + host);
    EXPECT_EQ(send(rotate)->status, 404U);
    EXPECT_EQ(credential_write_calls_, 0);
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayAdminHistory, RejectsRemoteHostOriginDuplicateAuthBodyAndUnboundedPages) {
    auto wrong_host = admin_request("admin-token", "/v1/admin/audit/counts");
    wrong_host.set(http::field::host, "example.invalid");
    EXPECT_EQ(send(wrong_host)->status, 403U);

    auto wrong_origin = admin_request("admin-token", "/v1/admin/audit/counts");
    wrong_origin.set(http::field::origin, "https://example.invalid");
    EXPECT_EQ(send(wrong_origin)->status, 403U);

    auto duplicate_auth = admin_request("admin-token", "/v1/admin/audit/counts");
    duplicate_auth.insert(http::field::authorization, "Bearer admin-token");
    EXPECT_EQ(send(duplicate_auth)->status, 400U);

    auto duplicate_host = admin_request("admin-token", "/v1/admin/audit/counts");
    duplicate_host.insert(http::field::host, "127.0.0.1:" + std::to_string(port_));
    EXPECT_EQ(send(duplicate_host)->status, 403U);

    auto duplicate_origin = admin_request("admin-token", "/v1/admin/audit/counts");
    duplicate_origin.insert(http::field::origin, "https://127.0.0.1:" + std::to_string(port_));
    EXPECT_EQ(send(duplicate_origin)->status, 403U);

    auto remote = admin_request("admin-token", "/v1/admin/audit/counts");
    const auto remote_reply = send(remote, nullptr, false, "127.0.0.2");
    ASSERT_TRUE(remote_reply);
    EXPECT_EQ(remote_reply->status, 403U);

    EXPECT_EQ(send(admin_request("admin-token", "/v1/admin/audit/events?page=40"))->status, 400U);
    EXPECT_EQ(send(admin_request("admin-token", "/v1/admin/audit/events?page=0&page=1"))->status, 400U);
    EXPECT_EQ(send(admin_request("admin-token", "/v1/admin/audit/egress/not-an-id"))->status, 400U);

    auto body = admin_request("admin-token", "/v1/admin/audit/counts");
    body.body() = "synthetic-body-marker";
    EXPECT_EQ(send(body)->status, 400U);
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayAdminHistory, AllowsOnlyOneConcurrentAdminRead) {
    const std::string padding(1024, 'x');
    for (int i = 0; i < 7500; ++i) {
        ASSERT_TRUE(audit_->append("request", "info", {{"origin", "dept-a"}, {"status", 200},
            {"result", "pass"}, {"padding", padding}, {"n", i}}));
    }
    std::barrier start(3);
    std::array<std::optional<Reply>, 2> replies;
    std::thread first([&] {
        start.arrive_and_wait();
        replies[0] = send(admin_request("admin-token", "/v1/admin/audit/counts"));
    });
    std::thread second([&] {
        start.arrive_and_wait();
        replies[1] = send(admin_request("admin-token", "/v1/admin/audit/counts"));
    });
    start.arrive_and_wait();
    first.join();
    second.join();
    ASSERT_TRUE(replies[0]);
    ASSERT_TRUE(replies[1]);
    const auto overloads = static_cast<int>(replies[0]->status == 503U && code_of(*replies[0]) == "overloaded") +
                           static_cast<int>(replies[1]->status == 503U && code_of(*replies[1]) == "overloaded");
    const auto successes = static_cast<int>(replies[0]->status == 200U) + static_cast<int>(replies[1]->status == 200U);
    EXPECT_EQ(overloads, 1);
    EXPECT_EQ(successes, 1);
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayAdminHistory, LargeDetailIsOutOfRangeWhileAggregateRemainsAvailable) {
    constexpr std::string_view request_id = "chatcmpl-pa-fedcba987654321001234567";
    ASSERT_TRUE(audit_->append("egress", "info", {{"request_id", request_id},
        {"sent", std::string(140U << 10, 'x')}}));
    const auto counts = send(admin_request("admin-token", "/v1/admin/audit/counts"));
    ASSERT_TRUE(counts);
    ASSERT_EQ(counts->status, 200U);
    EXPECT_EQ(nlohmann::json::parse(counts->body)["counts"]["egress_prepared"], 1);

    const auto detail = send(admin_request("admin-token", "/v1/admin/audit/egress/" + std::string(request_id)));
    ASSERT_TRUE(detail);
    EXPECT_EQ(detail->status, 200U);
    EXPECT_EQ(nlohmann::json::parse(detail->body)["status"], "out_of_range");
    EXPECT_EQ(detail->body.find(std::string(140U << 10, 'x')), std::string::npos);
}

TEST_F(GatewayAdminHistory, CorruptRecentAuditDoesNotReturnStoredRequestText) {
    constexpr std::string_view request_id = "chatcmpl-pa-abcdef0123456789abcdef01";
    constexpr std::string_view marker = "SYNTHETIC_TOKENIZED_MARKER";
    ASSERT_TRUE(audit_->append("egress", "info", {{"request_id", request_id},
        {"sent", nlohmann::json{{"model", "demo-alias"}, {"messages", nlohmann::json::array({
            {{"role", "user"}, {"content", marker}}})}}}}));
    std::filesystem::path current_log;
    for (const auto& entry : std::filesystem::directory_iterator(audit_->dir())) {
        if (entry.path().extension() == ".jsonl") current_log = entry.path();
    }
    ASSERT_FALSE(current_log.empty());
    std::ifstream input(current_log, std::ios::binary);
    std::string line;
    ASSERT_TRUE(std::getline(input, line));
    const auto hash = line.find("\"hash\":\"");
    ASSERT_NE(hash, std::string::npos);
    line[hash + 8] = line[hash + 8] == '0' ? '1' : '0';
    std::ofstream output(current_log, std::ios::binary | std::ios::trunc);
    output << line << '\n';
    output.close();

    const auto reply = send(admin_request("admin-token", "/v1/admin/audit/egress/" + std::string(request_id)));
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 503U);
    EXPECT_EQ(reply->body.find(marker), std::string::npos);
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayAdminHistory, FailedReadAuditWriteReturnsNoDetail) {
    constexpr std::string_view request_id = "chatcmpl-pa-00112233445566778899aabb";
    constexpr std::string_view marker = "SYNTHETIC_TOKENIZED_MARKER";
    ASSERT_TRUE(audit_->append("egress", "info", {{"request_id", request_id},
        {"sent", nlohmann::json{{"model", "demo-alias"}, {"messages", nlohmann::json::array({
            {{"role", "user"}, {"content", marker}}})}}}}));
    std::filesystem::path current_log;
    for (const auto& entry : std::filesystem::directory_iterator(audit_->dir())) {
        if (entry.path().extension() == ".jsonl") current_log = entry.path();
    }
    ASSERT_FALSE(current_log.empty());
    const auto original_permissions = std::filesystem::status(current_log).permissions();
    std::error_code permission_error;
    std::filesystem::permissions(current_log, std::filesystem::perms::owner_read,
                                 std::filesystem::perm_options::replace, permission_error);
    ASSERT_FALSE(permission_error);
    const auto reply = send(admin_request("admin-token", "/v1/admin/audit/egress/" + std::string(request_id)));
    std::filesystem::permissions(current_log, original_permissions, std::filesystem::perm_options::replace, permission_error);
    ASSERT_FALSE(permission_error);
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 503U);
    EXPECT_EQ(reply->body.find(marker), std::string::npos);
    EXPECT_EQ(handled(), 0);
}

TEST_F(GatewayCredentialRotation, ReplacesOnlyTheConfiguredCredentialAndKeepsSecretsOutOfAudit) {
    constexpr std::string_view marker = "synthetic-new-secret";
    const auto reply = send(credential_request("open-token", R"({"credential":"synthetic-new-secret"})"));
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 200u);
    EXPECT_EQ(reply->body, R"({"ok":true})");
    EXPECT_EQ(reply->body.find(marker), std::string::npos);
    EXPECT_EQ(reply->body.find(credential_file_.string()), std::string::npos);
    EXPECT_EQ(handled(), 0);
    EXPECT_EQ(store_calls_, 1);
    const auto stored = prompt_airlock::provider::load_credential(credential_file_);
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->view(), marker);
    bool recorded_attempt = false;
    for (const auto& entry : std::filesystem::directory_iterator(audit_->dir())) {
        if (entry.path().extension() != ".jsonl") continue;
        std::ifstream input(entry.path());
        for (std::string line; std::getline(input, line);) {
            EXPECT_EQ(line.find(marker), std::string::npos);
            EXPECT_EQ(line.find(credential_file_.string()), std::string::npos);
            const auto record = nlohmann::json::parse(line);
            if (record["kind"] == "credential_rotation") {
                EXPECT_EQ(record["result"], "attempt");
                EXPECT_EQ(record["reason"], "credential_rotation");
                recorded_attempt = true;
            }
        }
    }
    EXPECT_TRUE(recorded_attempt);
}

TEST_F(GatewayCredentialRotation, RejectsOtherOriginsGradesHostsOriginsAndAddressesBeforeWriting) {
    auto other_origin = credential_request("declare-token", R"({"credential":"should-not-store"})");
    other_origin.set("X-Prompt-Airlock-Grade", "O");
    ASSERT_EQ(send(other_origin)->status, 404u);

    auto private_grade = credential_request("open-token", R"({"credential":"should-not-store"})");
    private_grade.set("X-Prompt-Airlock-Grade", "S");
    ASSERT_EQ(send(private_grade)->status, 403u);

    auto wrong_host = credential_request("open-token", R"({"credential":"should-not-store"})");
    wrong_host.set(http::field::host, "localhost:" + std::to_string(port_));
    ASSERT_EQ(send(wrong_host)->status, 403u);

    auto wrong_origin = credential_request("open-token", R"({"credential":"should-not-store"})");
    wrong_origin.set(http::field::origin, "https://example.invalid");
    ASSERT_EQ(send(wrong_origin)->status, 403u);

    auto wrong_address = credential_request("open-token", R"({"credential":"should-not-store"})");
    const auto address_reply = send(wrong_address, nullptr, false, "127.0.0.2");
    ASSERT_TRUE(address_reply);
    EXPECT_EQ(address_reply->status, 403u);
    EXPECT_EQ(store_calls_, 0);
    EXPECT_EQ(handled(), 0);
    const auto stored = prompt_airlock::provider::load_credential(credential_file_);
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->view(), "old-credential");
}

TEST_F(GatewayCredentialRotation, RejectsCredentialBodiesWithExtraDuplicateOrInvalidValues) {
    const std::vector<std::string> bodies = {
        R"({"credential":"secret","path":"other"})",
        R"({"credential":"first-secret","credential":"second-secret"})",
        R"({"credential":""})",
        R"({"credential":"not a token"})",
        R"({"credential":12})",
        R"([{"credential":"secret"}])",
    };
    for (const auto& body : bodies) {
        const auto reply = send(credential_request("open-token", body));
        ASSERT_TRUE(reply);
        EXPECT_EQ(reply->status, 400u) << body;
        EXPECT_EQ(reply->body.find("secret"), std::string::npos);
        EXPECT_EQ(reply->body.find("other"), std::string::npos);
    }
    EXPECT_EQ(store_calls_, 0);
    EXPECT_EQ(handled(), 0);
    const auto stored = prompt_airlock::provider::load_credential(credential_file_);
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->view(), "old-credential");
    for (const auto& entry : std::filesystem::directory_iterator(audit_->dir())) {
        if (entry.path().extension() != ".jsonl") continue;
        std::ifstream input(entry.path());
        for (std::string line; std::getline(input, line);) {
            EXPECT_EQ(line.find("first-secret"), std::string::npos);
            EXPECT_EQ(line.find("second-secret"), std::string::npos);
            EXPECT_EQ(line.find("other"), std::string::npos);
            EXPECT_EQ(line.find(credential_file_.string()), std::string::npos);
        }
    }
}

TEST_F(GatewayCredentialRotation, EnforcesTheCredentialBodyLimit) {
    const auto body = std::string("{\"credential\":\"") +
                      std::string(gw::credential_rotation_body_bytes, 'x') + "\"}";
    const auto reply = send(credential_request("open-token", body));
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 413u);
    EXPECT_EQ(store_calls_, 0);
    EXPECT_EQ(handled(), 0);
    const auto stored = prompt_airlock::provider::load_credential(credential_file_);
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->view(), "old-credential");
}

TEST_F(GatewayCredentialRotation, AuditFailureDoesNotStartReplacement) {
    const auto audit_dir = audit_->dir();
    std::filesystem::remove_all(audit_dir);
    { std::ofstream blocked(audit_dir); blocked << "not a directory"; }
    const auto reply = send(credential_request("open-token", "{\"credential\":\"synthetic-secret\"}"));
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 503u);
    EXPECT_EQ(code_of(*reply), "unavailable");
    EXPECT_EQ(store_calls_, 0);
    EXPECT_EQ(handled(), 0);
    std::filesystem::remove(audit_dir);
    const auto stored = prompt_airlock::provider::load_credential(credential_file_);
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->view(), "old-credential");
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

TEST_F(GatewayServer, ClientDisconnectCancelsTheRunningHandler) {
    hold_ = true;
    asio::io_context io;
    beast::ssl_stream<beast::tcp_stream> stream(io, *client_tls_);
    SSL_set_tlsext_host_name(stream.native_handle(), "localhost");
    SSL_set1_host(stream.native_handle(), "localhost");
    ASSERT_FALSE(pa_test::retry_connect(beast::get_lowest_layer(stream), tcp::endpoint(asio::ip::make_address("127.0.0.1"), port_)));
    stream.handshake(asio::ssl::stream_base::client);
    auto req = request("open-token");
    req.prepare_payload();
    http::write(stream, req);
    std::unique_lock lock(mutex_);
    ASSERT_TRUE(changed_.wait_for(lock, std::chrono::seconds(5), [&] { return handled_ == 1; }));
    lock.unlock();
    beast::get_lowest_layer(stream).socket().close();  // TLS 종료 알림 없이 끊는다(시간 초과로 떠나는 클라이언트)
    lock.lock();
    // handler 가 10초를 다 쓰지 않고 취소를 받는다
    EXPECT_TRUE(changed_.wait_for(lock, std::chrono::seconds(5), [&] { return cancelled_; }));
}

}  // namespace
class GatewayLargeServer : public GatewayServer {
protected:
    std::size_t body_limit() const override { return 44U << 20; }
};

class GatewayCompatServer : public GatewayLargeServer {
protected:
    bool compatibility() const override { return true; }
};

TEST_F(GatewayCompatServer, ConfirmationIsARegularReplyWithACanonicalLocalApprovalLink) {
    {
        std::scoped_lock lock(mutex_);
        response_ = gw::confirm_response(std::string(32, 'a'), {"CONFIDENTIAL_MARKER"});
    }
    const auto reply = send(request("open-token"));
    ASSERT_TRUE(reply);
    EXPECT_EQ(reply->status, 200U);
    const auto body = nlohmann::json::parse(reply->body);
    EXPECT_EQ(body["prompt_airlock"]["decision"], "confirmation_required");
    const auto url = "https://127.0.0.1:" + std::to_string(port_) + "/console/confirm?token=" + std::string(32, 'a');
    EXPECT_EQ(body["prompt_airlock"]["approval_url"], url);
    const auto message = gw::parse_provider_answer(reply->body);
    ASSERT_TRUE(message);
    EXPECT_NE(message->content.view().find(url), std::string_view::npos);
    EXPECT_FALSE(reply->keep_alive);
}

TEST_F(GatewayCompatServer, PolicyBlocksRemainVisibleAndUnreadRequestsClose) {
    {
        std::scoped_lock lock(mutex_);
        response_ = gw::error_response(core::UserRejection{core::ReasonCode::EntityBlocked, {}});
    }
    auto blocked = request("open-token", R"({"canary":"private-value"})");
    const auto rule = send(blocked);
    ASSERT_TRUE(rule);
    EXPECT_EQ(rule->status, 200U);
    EXPECT_EQ(nlohmann::json::parse(rule->body)["prompt_airlock"]["decision"], "blocked");
    EXPECT_EQ(rule->body.find("private-value"), std::string::npos);
    EXPECT_FALSE(rule->keep_alive);
    const auto before = handled();
    for (const auto grade : {"C", "S", "unknown"}) {
        blocked.set("X-Prompt-Airlock-Grade", grade);
        const auto reply = send(blocked);
        ASSERT_TRUE(reply);
        EXPECT_EQ(reply->status, 200U);
        EXPECT_EQ(nlohmann::json::parse(reply->body)["prompt_airlock"]["decision"], "blocked");
        EXPECT_EQ(reply->body.find("private-value"), std::string::npos);
        EXPECT_FALSE(reply->keep_alive);
    }
    EXPECT_EQ(handled(), before);
}

TEST_F(GatewayCompatServer, ProviderAndInputErrorsKeepTheirOriginalFailureStatus) {
    for (const auto error : {gw::EntryError::ProviderFailed, gw::EntryError::ProviderAuthentication,
                             gw::EntryError::ProviderRateLimited, gw::EntryError::ProviderTimeout,
                             gw::EntryError::ProviderUnavailable, gw::EntryError::BadRequest,
                             gw::EntryError::Unavailable}) {
        const auto expected = gw::error_response(error);
        {
            std::scoped_lock lock(mutex_);
            response_ = expected;
        }
        const auto reply = send(request("open-token"));
        ASSERT_TRUE(reply);
        EXPECT_EQ(reply->status, expected.status);
        EXPECT_EQ(reply->body, expected.body);
        EXPECT_FALSE(nlohmann::json::parse(reply->body).contains("prompt_airlock"));
    }
}

TEST_F(GatewayLargeServer, ApprovalRequiresLocalAuthorityOriginAndItsOwnBodyLimit) {
    auto approval = request("open-token", R"({"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})");
    approval.target("/v1/confirmations/approve");
    EXPECT_EQ(send(approval)->status, 403U);
    const auto host = "127.0.0.1:" + std::to_string(port_);
    approval.set(http::field::host, host);
    approval.set(http::field::origin, "https://example.invalid");
    EXPECT_EQ(send(approval)->status, 403U);
    approval.set(http::field::origin, "https://" + host);
    approval.set("X-Prompt-Airlock-Confirm", std::string(32, 'a'));
    EXPECT_EQ(send(approval)->status, 400U);
    approval.erase("X-Prompt-Airlock-Confirm");
    approval.body() = std::string(gw::confirm_body_bytes + 1, ' ');
    EXPECT_EQ(send(approval)->status, 413U);
    approval.body() = R"({"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})";
    approval.set("X-Prompt-Airlock-Grade", "S");
    EXPECT_EQ(send(approval)->status, 403U);
    approval.erase("X-Prompt-Airlock-Grade");
    approval.erase(http::field::authorization);
    EXPECT_EQ(send(approval)->status, 401U);
    EXPECT_EQ(handled(), 0);
    approval.set(http::field::authorization, "Bearer open-token");
    EXPECT_EQ(send(approval)->status, 200U);
    EXPECT_EQ(handled(), 1);
    std::scoped_lock lock(mutex_);
    EXPECT_EQ(last_purpose_, gw::RequestPurpose::Approve);
}

TEST_F(GatewayLargeServer, CountsChunkedAndFixedUploadsAndReleasesSharedBudget) {
    retain_uploads_ = true;
    const std::string large(70000, 'x');
    const auto first = send(request("open-token", large));
    ASSERT_TRUE(first);
    EXPECT_EQ(first->status, 200U);
    {
        std::scoped_lock lock(mutex_);
        EXPECT_EQ(last_body_, large);
    }
    const auto second = send(request("open-token", large), nullptr, true);
    ASSERT_TRUE(second);
    EXPECT_EQ(second->status, 200U);
    {
        std::scoped_lock lock(mutex_);
        EXPECT_EQ(last_body_, large);
    }
    const auto overloaded = send(request("open-token", large), nullptr, true);
    ASSERT_TRUE(overloaded);
    EXPECT_EQ(overloaded->status, 503U);
    EXPECT_EQ(code_of(*overloaded), "overloaded");
    const auto small = send(request("open-token", "small"));
    ASSERT_TRUE(small);
    EXPECT_EQ(small->status, 200U);
    {
        std::scoped_lock lock(mutex_);
        uploads_.clear();
    }
    const auto retry = send(request("open-token", large));
    ASSERT_TRUE(retry);
    EXPECT_EQ(retry->status, 200U);
    EXPECT_EQ(handled(), 4);
}
