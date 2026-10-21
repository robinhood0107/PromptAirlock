// HTTP 로 끝까지: 기관 앱(시험 클라이언트) → HTTPS 게이트웨이 → 실제 탐지기(NER 포함)·실제 Vault → mock provider.
// 값은 모두 합성이다. mock provider 가 받은 본문(밖으로 나간 내용)에 원문이 없는지와, 거절 때 provider 호출이 0 인지를 본다.
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>

#include <optional>
#include <span>
#include <string>
#include <thread>

#include "mock_provider.hpp"
#include "prompt_airlock/core/sha256.hpp"
#include "prompt_airlock/gateway/pipeline.hpp"
#include "prompt_airlock/gateway/server.hpp"
#include "prompt_airlock/ner/pool.hpp"
#include "prompt_airlock/provider/https_client.hpp"
#include "prompt_airlock/tls/context.hpp"
#include "prompt_airlock/vault_client/service.hpp"
#include "test_cert.hpp"

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace core = prompt_airlock::core;
namespace gw = prompt_airlock::gateway;
using json = nlohmann::json;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

const std::string person = "김민준";
const std::string phone = "010-2345-6789";
const std::string email = "user1@example.invalid";
const std::string institution = "한빛시청";

std::string hash_of(std::string_view token) {
    return core::sha256_hex(std::as_bytes(std::span(token.data(), token.size())));
}

struct Reply {
    unsigned status = 0;
    json body;
};

class GatewayHttp : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        auto pool = prompt_airlock::ner::NerPool::make(PA_NER_MODEL_DIR);
        ASSERT_TRUE(pool.has_value());
        ner_ = *pool;
    }
    static void TearDownTestSuite() { ner_.reset(); }

    void SetUp() override {
        cert_ = pa_test::make_test_certificate();
        auto server_tls = prompt_airlock::tls::make_server_context(cert_.certificate_pem, cert_.private_key_pem);
        auto client_tls = prompt_airlock::tls::make_client_context(std::string_view{cert_.certificate_pem});
        ASSERT_TRUE(server_tls && client_tls);
        server_tls_.emplace(std::move(*server_tls));
        client_tls_.emplace(std::move(*client_tls));

        const std::string_view terms[] = {institution};
        auto detectors = prompt_airlock::detect::Detectors::make(terms, ner_);
        ASSERT_TRUE(detectors.has_value());
        detectors_.emplace(std::move(*detectors));

        prompt_airlock::vault_client::ServiceOptions vault_options;
        vault_options.exe = PA_VAULT_EXE;
        vault_options.connection.io_timeout = 3000ms;
        vault_.emplace(vault_options);

        const tcp::endpoint loopback(asio::ip::make_address("127.0.0.1"), 0);
        mock_.emplace(io_, *server_tls_, loopback, pa_mock::MockOptions{"provider-secret", {}});
        mock_->start();
        provider_.emplace(*client_tls_,
                          prompt_airlock::provider::Endpoint{"127.0.0.1", mock_->local_endpoint().port(),
                                                             "/v1/chat/completions"},
                          core::SensitiveText::copy_of("provider-secret"));
        pipeline_.emplace(
            *detectors_,
            [this]() -> std::expected<gw::PseudonymScope, core::VaultError> {
                auto scope = vault_->open_scope();
                if (!scope) {
                    return std::unexpected(core::VaultError::Unavailable);
                }
                return gw::PseudonymScope(std::move(*scope));
            },
            [this](std::string body) { return provider_->send(std::move(body)); }, core::OutputTokenCap::standard(),
            "demo-alias");
        server_.emplace(io_, *server_tls_, loopback, auth_,
                        [this](gw::AcceptedRequest request) { return pipeline_->handle(std::move(request)); });
        server_->start();
        thread_ = std::thread([this] { io_.run(); });
    }

    void TearDown() override {
        server_->stop();
        mock_->stop();
        io_.stop();
        thread_.join();
    }

    Reply post(std::string_view text, std::string_view grade = {}) {
        asio::io_context io;
        beast::ssl_stream<beast::tcp_stream> stream(io, *client_tls_);
        SSL_set1_host(stream.native_handle(), "localhost");
        beast::get_lowest_layer(stream).expires_after(30s);
        beast::get_lowest_layer(stream).connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"),
                                                              server_->local_endpoint().port()));
        stream.handshake(asio::ssl::stream_base::client);
        http::request<http::string_body> req{http::verb::post, "/v1/chat/completions", 11};
        req.set(http::field::host, "localhost");
        req.set(http::field::content_type, "application/json");
        req.set(http::field::authorization, "Bearer desk-token");
        if (!grade.empty()) {
            req.set("X-Prompt-Airlock-Grade", grade);
        }
        req.body() = json{{"model", "any"}, {"messages", json::array({{{"role", "user"}, {"content", text}}})}}.dump();
        req.prepare_payload();
        http::write(stream, req);
        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(stream, buffer, res);
        return {res.result_int(), json::parse(res.body())};
    }

    static inline std::shared_ptr<const prompt_airlock::detect::NerScanner> ner_;
    pa_test::TestCertificate cert_;
    std::optional<asio::ssl::context> server_tls_;
    std::optional<asio::ssl::context> client_tls_;
    std::optional<prompt_airlock::detect::Detectors> detectors_;
    std::optional<prompt_airlock::vault_client::VaultService> vault_;
    gw::Authenticator auth_{{{"desk", hash_of("desk-token"), core::GradePolicy::OOnly}}};
    asio::io_context io_;
    std::optional<pa_mock::MockProvider> mock_;
    std::optional<prompt_airlock::provider::HttpsClient> provider_;
    std::optional<gw::Pipeline> pipeline_;
    std::optional<gw::Server> server_;
    std::thread thread_;
};

TEST_F(GatewayHttp, EgressCarriesTokensInsteadOfValues) {
    (void)post(institution + " " + person + " 주무관에게 " + phone + " 또는 " + email + " 로 회의 일정을 알려 주세요");
    const auto sent = mock_->received();
    ASSERT_EQ(sent.size(), 1u);
    for (const std::string& value : {person, phone, email, institution}) {
        EXPECT_EQ(sent.front().find(value), std::string::npos) << "원문이 밖으로 나갔다";
    }
    const json body = json::parse(sent.front());
    EXPECT_EQ(body["model"], "demo-alias");
    EXPECT_NE(body["messages"][0]["content"].get<std::string>().find(std::string(core::token_open)), std::string::npos);
}

TEST_F(GatewayHttp, RejectionsNeverReachProvider) {
    const auto blocked = post("제 주민번호는 900101-1234567 입니다");
    EXPECT_EQ(blocked.status, 400u);
    EXPECT_EQ(blocked.body["error"]["code"].get<std::string>(), core::reason_code_name(core::ReasonCode::EntityBlocked));
    const auto encoded = post("확인 부탁: OTAwMTAxLTEyMzQ1Njc=");
    EXPECT_EQ(encoded.status, 400u);
    const auto sensitive = post("회의 안건 정리", "S");
    EXPECT_EQ(sensitive.status, 403u);
    EXPECT_TRUE(mock_->received().empty());
}

}  // namespace
