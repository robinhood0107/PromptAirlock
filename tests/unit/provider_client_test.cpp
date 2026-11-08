// provider 클라이언트 시험: 같은 프로세스에 mock provider 를 TLS 로 띄우고 실제로 보낸다.
#include "prompt_airlock/provider/https_client.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <array>
#include <future>
#include <optional>
#include <thread>
#include <vector>

#include "mock_provider.hpp"
#include "prompt_airlock/tls/context.hpp"
#include "socket_retry.hpp"
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
        pa_test::retry_listen([&] { mock_.emplace(io_, *server_tls_, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0),
                      pa_mock::MockOptions{"provider-secret", {}}); });
        mock_->start();
        thread_ = std::thread([this] { io_.run(); });
    }
    void TearDown() override {
        mock_->stop();
        thread_.join();  // 남은 연결이 끝나 io.run 이 스스로 돌아온다(강제로 멈추면 Windows 에서 다음 listen 이 드물게 실패)
    }

    std::expected<gw::ProviderReply, gw::ProviderError> send(std::string host, std::string credential,
                                                             std::string body) {
        EXPECT_TRUE(pv::store_credential(credential_file_, credential).has_value());
        return send_with_file(std::move(host), std::move(body));
    }
    std::expected<gw::ProviderReply, gw::ProviderError> send_with_file(std::string host, std::string body) {
        pv::HttpsClient client(*client_tls_, {std::move(host), mock_->local_endpoint().port(), "/v1/chat/completions"},
                               credential_file_, {std::chrono::seconds(5)});
        asio::io_context io;
        auto future = asio::co_spawn(io, client.send(std::move(body)), asio::use_future);
        io.run();
        return future.get();
    }

    void set_options(pa_mock::MockOptions options) {
        mock_->stop();
        thread_.join();
        mock_.reset();
        io_.restart();
        mock_.emplace(io_, *server_tls_, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0), std::move(options));
        mock_->start();
        thread_ = std::thread([this] { io_.run(); });
    }

    std::expected<gw::ProviderReply, gw::ProviderError> measured_send(pv::ClientTimings& timing,
                                                                   std::chrono::seconds timeout = std::chrono::seconds(5)) {
        EXPECT_TRUE(pv::store_credential(credential_file_, "provider-secret").has_value());
        pv::HttpsClient client(*client_tls_, {"127.0.0.1", mock_->local_endpoint().port(), "/v1/chat/completions"},
                               credential_file_, {timeout});
        asio::io_context io;
        auto future = asio::co_spawn(io, client.send("{}", &timing), asio::use_future);
        io.run();
        return future.get();
    }

    const std::filesystem::path credential_file_ = std::filesystem::temp_directory_path() / "pa-provider-client.cred";

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
    ASSERT_TRUE(pv::store_credential(credential_file_, "provider-secret").has_value());
    pv::HttpsClient client(*tls, {"127.0.0.1", mock_->local_endpoint().port(), "/v1/chat/completions"},
                           credential_file_, {std::chrono::seconds(5)});
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

TEST_F(ProviderClient, UsesReplacedCredentialOnNextRequest) {
    // 실행 중에 자격 증명 파일을 바꿔 끼우면 재기동 없이 다음 요청부터 새 값을 쓴다(ADR 0026).
    EXPECT_EQ(send("127.0.0.1", "expired-token", "{}")->status, 401u);
    EXPECT_EQ(send("127.0.0.1", "provider-secret", "{}")->status, 200u);
    EXPECT_EQ(mock_->received().size(), 1u);
}

TEST_F(ProviderClient, MeasuresBodyDelaySeparately) {
    pa_mock::MockOptions options{"provider-secret", {}};
    options.body_delay = std::chrono::milliseconds(120);
    set_options(options);
    pv::ClientTimings timing;
    ASSERT_TRUE(measured_send(timing));
    // 스케줄링으로 헤더 소비가 늦어지면 대기의 일부는 헤더 구간에 들어간다.
    EXPECT_GE(timing.phases[static_cast<std::size_t>(pv::ClientPhase::Headers)] +
                  timing.phases[static_cast<std::size_t>(pv::ClientPhase::Body)], std::chrono::milliseconds(100));
    EXPECT_EQ(timing.last, pv::ClientPhase::Shutdown);
    EXPECT_GE(timing.total, timing.phases[static_cast<std::size_t>(pv::ClientPhase::Body)]);
}

TEST_F(ProviderClient, MeasuresShutdownDelaySeparately) {
    pa_mock::MockOptions options{"provider-secret", {}};
    options.shutdown_delay = std::chrono::milliseconds(120);
    set_options(options);
    pv::ClientTimings timing;
    ASSERT_TRUE(measured_send(timing));
    EXPECT_GE(timing.phases[static_cast<std::size_t>(pv::ClientPhase::Shutdown)], std::chrono::milliseconds(100));
    EXPECT_EQ(timing.last, pv::ClientPhase::Shutdown);
}

TEST_F(ProviderClient, AcceptsOnlyCompleteResponsesWithoutShutdownNotification) {
    for (const auto mode : {pa_mock::BodyMode::Standard, pa_mock::BodyMode::Chunked, pa_mock::BodyMode::Truncated,
                            pa_mock::BodyMode::CloseDelimited, pa_mock::BodyMode::NoBody}) {
        SCOPED_TRACE(static_cast<int>(mode));
        pa_mock::MockOptions options{"provider-secret", {}};
        options.body_mode = mode;
        options.shutdown_mode = pa_mock::ShutdownMode::Abrupt;
        set_options(options);
        pv::ClientTimings timing;
        const auto result = measured_send(timing);
        EXPECT_EQ(result.has_value(), mode != pa_mock::BodyMode::Truncated && mode != pa_mock::BodyMode::CloseDelimited);
    }
}

TEST_F(ProviderClient, AcceptsCloseDelimitedResponseWithSecureEof) {
    pa_mock::MockOptions options{"provider-secret", {}};
    options.body_mode = pa_mock::BodyMode::CloseDelimited;
    set_options(options);
    pv::ClientTimings timing;
    EXPECT_TRUE(measured_send(timing));
}

TEST_F(ProviderClient, SlowBodyStillTimesOut) {
    pa_mock::MockOptions options{"provider-secret", {}};
    options.body_delay = std::chrono::milliseconds(1500);
    set_options(options);
    pv::ClientTimings timing;
    const auto result = measured_send(timing, std::chrono::seconds(1));
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error(), gw::ProviderError::Timeout);
    EXPECT_EQ(timing.last, pv::ClientPhase::Body);
}

TEST_F(ProviderClient, ConcurrentTimingsStayRequestLocal) {
    ASSERT_TRUE(pv::store_credential(credential_file_, "provider-secret"));
    pv::HttpsClient client(*client_tls_, {"127.0.0.1", mock_->local_endpoint().port(), "/v1/chat/completions"},
                           credential_file_, {std::chrono::seconds(5)});
    asio::io_context io;
    std::array<pv::ClientTimings, 8> timings;
    std::vector<std::future<std::expected<gw::ProviderReply, gw::ProviderError>>> futures;
    for (auto& timing : timings) futures.push_back(asio::co_spawn(io, client.send("{}", &timing), asio::use_future));
    const auto missing_file = credential_file_.string() + ".missing";
    ASSERT_FALSE(std::filesystem::exists(missing_file));
    pv::HttpsClient unavailable(*client_tls_, {"127.0.0.1", mock_->local_endpoint().port(), "/v1/chat/completions"}, missing_file);
    pv::ClientTimings failed_timing;
    auto failed = asio::co_spawn(io, unavailable.send("{}", &failed_timing), asio::use_future);
    io.run();
    for (std::size_t i = 0; i < futures.size(); ++i) {
        ASSERT_TRUE(futures[i].get());
        EXPECT_EQ(timings[i].last, pv::ClientPhase::Shutdown);
        EXPECT_GT(timings[i].total.count(), 0);
    }
    EXPECT_EQ(failed.get().error(), gw::ProviderError::Unavailable);
    EXPECT_EQ(failed_timing.last, pv::ClientPhase::Credential);
    EXPECT_EQ(failed_timing.phases[static_cast<std::size_t>(pv::ClientPhase::Shutdown)].count(), 0);
    EXPECT_EQ(mock_->received().size(), timings.size());
}

TEST_F(ProviderClient, CancellationWhileReadingCannotReturnSuccess) {
    pa_mock::MockOptions options{"provider-secret", {}};
    options.body_delay = std::chrono::milliseconds(120);
    set_options(options);
    ASSERT_TRUE(pv::store_credential(credential_file_, "provider-secret"));
    pv::HttpsClient client(*client_tls_, {"127.0.0.1", mock_->local_endpoint().port(), "/v1/chat/completions"},
                           credential_file_);
    asio::io_context io;
    asio::cancellation_signal cancel;
    asio::steady_timer timer(io, std::chrono::milliseconds(40));
    timer.async_wait([&](auto) { cancel.emit(asio::cancellation_type::all); });
    pv::ClientTimings timing;
    auto future = asio::co_spawn(io, [&]() -> asio::awaitable<std::expected<gw::ProviderReply, gw::ProviderError>> {
        co_await asio::this_coro::throw_if_cancelled(false);
        co_return co_await client.send("{}", &timing);
    }, asio::bind_cancellation_slot(cancel.slot(), asio::use_future));
    io.run();
    EXPECT_FALSE(future.get());
    EXPECT_GT(timing.total.count(), 0);
}

TEST_F(ProviderClient, UnreadableCredentialMakesNoCall) {
    // 파일이 없거나 보호되지 않았으면 연결하지 않고 실패한다(실패하면 막는 쪽).
    std::filesystem::remove(credential_file_);
    EXPECT_EQ(send_with_file("127.0.0.1", "{}").error(), gw::ProviderError::Unavailable);
    std::ofstream(credential_file_, std::ios::binary | std::ios::trunc) << "provider-secret";
#ifndef _WIN32
    std::filesystem::permissions(credential_file_, std::filesystem::perms::others_read, std::filesystem::perm_options::add);
#endif
    EXPECT_EQ(send_with_file("127.0.0.1", "{}").error(), gw::ProviderError::Unavailable);
    EXPECT_TRUE(mock_->received().empty());
    EXPECT_EQ(mock_->connections(), 0u);
}

TEST(ProviderCredential, StoreReplacesFileAtomically) {
    const auto path = std::filesystem::temp_directory_path() / "pa-cred-store.bin";
    std::filesystem::remove(path);
    ASSERT_TRUE(pv::store_credential(path, "first-token\n").has_value());
    ASSERT_TRUE(pv::store_credential(path, "second-token").has_value());  // 있는 파일을 바꿔 끼운다
    const auto read = pv::load_credential(path);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->view(), "second-token");
    EXPECT_FALSE(std::filesystem::exists(path.string() + ".tmp"));
#ifndef _WIN32
    const auto perms = std::filesystem::status(path).permissions();
    EXPECT_EQ(perms & (std::filesystem::perms::group_all | std::filesystem::perms::others_all), std::filesystem::perms::none);
#endif
}

TEST(ProviderCredential, ReadsOnlyProtectedFiles) {
    const auto dir = std::filesystem::temp_directory_path();
    const auto write = [&](const char* name, std::string_view bytes, bool owner_only) {
        const auto path = dir / name;
        std::ofstream(path, std::ios::binary | std::ios::trunc) << bytes;
        if (owner_only) {
            std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                         std::filesystem::perm_options::replace);
        }
        return path;
    };
    // 보호하지 않은 평문 파일은 읽지 않는다(Windows: DPAPI 아님, Linux: 다른 사용자 권한 있음)
    std::filesystem::remove(dir / "pa-cred-plain.txt");
    EXPECT_EQ(pv::load_credential(write("pa-cred-plain.txt", "sk-test-123\n", false)).error(),
              pv::CredentialError::NotProtected);
    const auto sealed = pv::protect_credential("sk-test-123\r\n");
    ASSERT_TRUE(sealed.has_value());
    std::filesystem::remove(dir / "pa-cred-ok.bin");
    const auto ok = pv::load_credential(write("pa-cred-ok.bin", *sealed, true));
    ASSERT_TRUE(ok.has_value());
    EXPECT_EQ(ok->view(), "sk-test-123");
    std::filesystem::remove(dir / "pa-cred-space.bin");
    EXPECT_EQ(pv::load_credential(write("pa-cred-space.bin", *pv::protect_credential("a b"), true)).error(),
              pv::CredentialError::InvalidCharacter);
    EXPECT_EQ(pv::load_credential(dir / "pa-cred-missing.txt").error(), pv::CredentialError::Unreadable);
}

}  // namespace
