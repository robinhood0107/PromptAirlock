// provider 클라이언트 시험: 같은 프로세스에 mock provider 를 TLS 로 띄우고 실제로 보낸다.
#include "prompt_airlock/provider/https_client.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <optional>
#include <thread>

#include "mock_provider.hpp"
#include "prompt_airlock/tls/context.hpp"
#include "test_cert.hpp"

namespace {

namespace asio = boost::asio;
namespace core = prompt_airlock::core;
namespace gw = prompt_airlock::gateway;
namespace pv = prompt_airlock::provider;
using tcp = asio::ip::tcp;

class ProviderClient : public ::testing::Test {
protected:
    void SetUp() override {
        cert_ = pa_test::make_test_certificate();
        auto server = prompt_airlock::tls::make_server_context(cert_.certificate_pem, cert_.private_key_pem);
        auto client = prompt_airlock::tls::make_client_context(std::string_view{cert_.certificate_pem});
        ASSERT_TRUE(server && client);
        server_tls_.emplace(std::move(*server));
        client_tls_.emplace(std::move(*client));
        mock_.emplace(io_, *server_tls_, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0),
                      pa_mock::MockOptions{"provider-secret", {}});
        mock_->start();
        thread_ = std::thread([this] { io_.run(); });
    }
    void TearDown() override {
        mock_->stop();
        io_.stop();
        thread_.join();
    }

    std::expected<gw::ProviderReply, gw::ProviderError> send(std::string host, std::string credential,
                                                             std::string body) {
        pv::HttpsClient client(*client_tls_, {std::move(host), mock_->local_endpoint().port(), "/v1/chat/completions"},
                               core::SensitiveText::copy_of(credential), {std::chrono::seconds(5)});
        asio::io_context io;
        auto future = asio::co_spawn(io, client.send(std::move(body)), asio::use_future);
        io.run();
        return future.get();
    }

    pa_test::TestCertificate cert_;
    std::optional<asio::ssl::context> server_tls_;
    std::optional<asio::ssl::context> client_tls_;
    asio::io_context io_;
    std::optional<pa_mock::MockProvider> mock_;
    std::thread thread_;
};

TEST_F(ProviderClient, SendsBodyAndReadsAnswer) {
    const std::string body = R"({"model":"demo","messages":[{"role":"user","content":"안녕하세요"}]})";
    const auto reply = send("127.0.0.1", "provider-secret", body);
    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(reply->status, 200u);
    const auto answer = nlohmann::json::parse(reply->body);
    EXPECT_EQ(answer["choices"][0]["message"]["content"], "받은 질문: 안녕하세요");
    ASSERT_EQ(mock_->received().size(), 1u);
    EXPECT_EQ(mock_->received().front(), body);
}

TEST_F(ProviderClient, VerifiesServerNameAgainstCertificate) {
    // 인증서는 localhost 와 127.0.0.1 에만 맞는다
    EXPECT_TRUE(send("localhost", "provider-secret", "{}").has_value());
    const auto wrong = send("127.0.0.2", "provider-secret", "{}");
    EXPECT_FALSE(wrong.has_value());
}

TEST_F(ProviderClient, RefusesUntrustedProvider) {
    const auto other = pa_test::make_test_certificate();
    auto tls = prompt_airlock::tls::make_client_context(std::string_view{other.certificate_pem});
    ASSERT_TRUE(tls.has_value());
    pv::HttpsClient client(*tls, {"127.0.0.1", mock_->local_endpoint().port(), "/v1/chat/completions"},
                           core::SensitiveText::copy_of("provider-secret"), {std::chrono::seconds(5)});
    asio::io_context io;
    auto future = asio::co_spawn(io, client.send("{}"), asio::use_future);
    io.run();
    EXPECT_FALSE(future.get().has_value());
    EXPECT_TRUE(mock_->received().empty());
}

TEST_F(ProviderClient, WrongCredentialIsAnErrorStatus) {
    const auto reply = send("127.0.0.1", "wrong", "{}");
    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(reply->status, 401u);
    EXPECT_TRUE(mock_->received().empty());
}

TEST(ProviderCredential, LoadsOneVisibleLine) {
    const auto dir = std::filesystem::temp_directory_path();
    const auto write = [&](const char* name, std::string_view text) {
        std::ofstream(dir / name, std::ios::binary) << text;
        return dir / name;
    };
    const auto ok = pv::load_credential(write("pa-cred-ok.txt", "sk-test-123\r\n"));
    ASSERT_TRUE(ok.has_value());
    EXPECT_EQ(ok->view(), "sk-test-123");
    EXPECT_EQ(pv::load_credential(write("pa-cred-empty.txt", "\n")).error(), pv::CredentialError::Empty);
    EXPECT_EQ(pv::load_credential(write("pa-cred-space.txt", "a b")).error(), pv::CredentialError::InvalidCharacter);
    EXPECT_EQ(pv::load_credential(dir / "pa-cred-missing.txt").error(), pv::CredentialError::Unreadable);
}

}  // namespace
