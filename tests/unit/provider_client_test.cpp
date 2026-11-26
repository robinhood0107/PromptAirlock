// provider 클라이언트 시험: 같은 프로세스에 mock provider 를 TLS 로 띄우고 실제로 보낸다.
#include "prompt_airlock/provider/https_client.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/post.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <iterator>
#include <optional>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

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
    std::expected<void, pv::ConnectCheckError> check_connection_with(
        asio::ssl::context& tls, std::string host, std::uint16_t port, const std::filesystem::path& credential_file,
        std::chrono::seconds timeout) {
        pv::HttpsClient client(tls, {std::move(host), port, "/v1/chat/completions"}, credential_file, {timeout});
        asio::io_context io;
        auto future = asio::co_spawn(io, client.check_connection(), asio::use_future);
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

TEST_F(ProviderClient, SendsConfiguredProtocolHeadersOnlyWhenConfigured) {
    pa_mock::MockOptions key_options{"provider-secret", {}};
    key_options.api_key_header_name = "x-goog-api-key";
    key_options.expected_target = "/models/demo:generateContent";
    key_options.expected_host = "127.0.0.1";
    key_options.require_post = true;
    key_options.require_json_content_type = true;
    key_options.require_connection_close = true;
    set_options(key_options);
    ASSERT_TRUE(pv::store_credential(credential_file_, "provider-secret"));
    const std::string generate_body = R"({"contents":[{"role":"user","parts":[{"text":"hello"}]}]})";
    pv::HttpsClient key_client(*client_tls_, {"127.0.0.1", mock_->local_endpoint().port(), key_options.expected_target,
                                             gw::ProviderCredentialMode::ApiKeyHeader}, credential_file_,
                              {std::chrono::seconds(5)});
    asio::io_context key_io;
    auto key_future = asio::co_spawn(key_io, key_client.send(generate_body), asio::use_future);
    key_io.run();
    ASSERT_TRUE(key_future.get());
    ASSERT_EQ(mock_->received().size(), 1u);
    EXPECT_EQ(mock_->received().front(), generate_body);

    pa_mock::MockOptions version_options{"provider-secret", {}};
    version_options.version_header_name = "x-test-version";
    version_options.version_header_value = "2026-11-20";
    version_options.expected_target = "/v1/messages";
    version_options.expected_host = "127.0.0.1";
    version_options.require_post = true;
    version_options.require_json_content_type = true;
    version_options.require_connection_close = true;
    set_options(version_options);
    const std::string messages_body = R"({"model":"demo","messages":[]})";
    pv::HttpsClient version_client(*client_tls_, {"127.0.0.1", mock_->local_endpoint().port(), version_options.expected_target,
                                                 gw::ProviderCredentialMode::Bearer, version_options.version_header_name,
                                                 version_options.version_header_value}, credential_file_,
                                  {std::chrono::seconds(5)});
    asio::io_context version_io;
    auto version_future = asio::co_spawn(version_io, version_client.send(messages_body), asio::use_future);
    version_io.run();
    ASSERT_TRUE(version_future.get());
    ASSERT_EQ(mock_->received().size(), 1u);
    EXPECT_EQ(mock_->received().front(), messages_body);
}

TEST_F(ProviderClient, RejectsDirectAndJsonEncodedCredentialEchoes) {
    const std::array<std::string_view, 2> response_bodies = {
        R"({"echo":"provider-secret"})",
        R"({"echo":"provider\u002dsecret"})",
    };
    for (const auto response_body : response_bodies) {
        pa_mock::MockOptions options{"provider-secret", {}};
        options.response_body = response_body;
        set_options(std::move(options));
        const auto result = send("127.0.0.1", "provider-secret", "{}");
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error(), gw::ProviderError::BadResponse);
        ASSERT_EQ(mock_->received().size(), 1u);
        EXPECT_EQ(mock_->received().front(), "{}");
    }
}

TEST_F(ProviderClient, VerifiesServerNameAgainstCertificate) {
    // 인증서는 localhost 와 127.0.0.1 에만 맞는다
    EXPECT_TRUE(send("localhost", "provider-secret", "{}").has_value());
    const auto wrong = send("127.0.0.2", "provider-secret", "{}");
    EXPECT_FALSE(wrong.has_value());
}

TEST_F(ProviderClient, CheckConnectionVerifiesTlsWithoutCredentialOrApplicationRequest) {
    const auto missing_credential = std::filesystem::path(credential_file_.string() + ".check-missing");
    std::filesystem::remove(missing_credential);
    const auto result = check_connection_with(*client_tls_, "127.0.0.1", mock_->local_endpoint().port(),
                                              missing_credential, std::chrono::seconds(5));
    ASSERT_TRUE(result);
    EXPECT_FALSE(std::filesystem::exists(missing_credential));
    EXPECT_EQ(mock_->connections(), 1u);
    EXPECT_TRUE(mock_->received().empty());
}

TEST_F(ProviderClient, CheckConnectionRejectsUntrustedCertificateWithoutApplicationRequest) {
    const auto other = pa_test::make_test_certificate();
    auto untrusted = prompt_airlock::tls::make_client_context(std::string_view{other.certificate_pem});
    ASSERT_TRUE(untrusted);
    const auto missing_credential = std::filesystem::path(credential_file_.string() + ".check-untrusted-missing");
    std::filesystem::remove(missing_credential);
    const auto result = check_connection_with(*untrusted, "127.0.0.1", mock_->local_endpoint().port(),
                                              missing_credential, std::chrono::seconds(5));
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error(), pv::ConnectCheckError::TlsHandshakeFailed);
    EXPECT_FALSE(std::filesystem::exists(missing_credential));
    EXPECT_EQ(mock_->connections(), 1u);
    EXPECT_TRUE(mock_->received().empty());
}

TEST_F(ProviderClient, CheckConnectionBoundsUnreachableTargetWithoutApplicationRequest) {
    asio::io_context unused_io;
    tcp::acceptor unused(unused_io);
    unused.open(tcp::v4());
    unused.bind(tcp::endpoint(asio::ip::address_v4::loopback(), 0));
    const auto port = unused.local_endpoint().port();
    const auto missing_credential = std::filesystem::path(credential_file_.string() + ".check-refused-missing");
    std::filesystem::remove(missing_credential);
    const auto started = std::chrono::steady_clock::now();
    const auto result = check_connection_with(*client_tls_, "127.0.0.1", port, missing_credential,
                                              std::chrono::seconds(2));
    const auto elapsed = std::chrono::steady_clock::now() - started;
    unused.close();
    ASSERT_FALSE(result);
    EXPECT_TRUE(result.error() == pv::ConnectCheckError::ConnectFailed ||
                result.error() == pv::ConnectCheckError::Timeout);
    EXPECT_LT(elapsed, std::chrono::seconds(3));
    EXPECT_FALSE(std::filesystem::exists(missing_credential));
    EXPECT_TRUE(mock_->received().empty());
}

TEST_F(ProviderClient, CheckConnectionTimesOutDuringTlsHandshakeWithoutApplicationRequest) {
    asio::io_context silent_io;
    tcp::acceptor acceptor(silent_io, tcp::endpoint(asio::ip::address_v4::loopback(), 0));
    tcp::socket peer(silent_io);
    asio::steady_timer hold(silent_io);
    std::atomic_bool accepted{false};
    std::promise<void> cleanup_done;
    auto cleanup_future = cleanup_done.get_future();
    acceptor.async_accept(peer, [&](const boost::system::error_code& error) {
        if (error) return;
        accepted.store(true, std::memory_order_relaxed);
        hold.expires_after(std::chrono::seconds(5));
        hold.async_wait([](const boost::system::error_code&) {});
    });
    std::thread server_thread([&] { silent_io.run(); });

    const auto missing_credential = std::filesystem::path(credential_file_.string() + ".check-timeout-missing");
    std::filesystem::remove(missing_credential);
    const auto result = check_connection_with(*client_tls_, "127.0.0.1", acceptor.local_endpoint().port(),
                                              missing_credential, std::chrono::seconds(1));
    asio::post(silent_io, [&] {
        boost::system::error_code ignored;
        hold.cancel();
        peer.close(ignored);
        acceptor.close(ignored);
        cleanup_done.set_value();
    });
    cleanup_future.wait();
    server_thread.join();

    ASSERT_TRUE(accepted.load(std::memory_order_relaxed));
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error(), pv::ConnectCheckError::Timeout);
    EXPECT_FALSE(std::filesystem::exists(missing_credential));
    EXPECT_TRUE(mock_->received().empty());
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
    EXPECT_EQ(mock_->connections(), 1u);
    EXPECT_TRUE(mock_->received().empty());
}

TEST_F(ProviderClient, WrongCredentialIsAnErrorStatus) {
    const auto reply = send("127.0.0.1", "wrong", "{}");
    ASSERT_TRUE(reply.has_value());
    EXPECT_EQ(reply->status, 401u);
    EXPECT_EQ(mock_->connections(), 1u);
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
    EXPECT_EQ(mock_->connections(), 1u);
    EXPECT_EQ(mock_->received().size(), 1u);
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
    const auto dir = std::filesystem::temp_directory_path() /
                     ("pa-cred-store-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(dir);
    const auto path = dir / "credential.bin";
    ASSERT_TRUE(pv::store_credential(path, "first-token\n").has_value());
    ASSERT_TRUE(pv::store_credential(path, "second-token").has_value());  // 있는 파일을 바꿔 끼운다
    const auto read = pv::load_credential(path);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->view(), "second-token");
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        EXPECT_FALSE(entry.path().filename().string().starts_with("credential.bin.tmp."));
    }
#ifndef _WIN32
    const auto perms = std::filesystem::status(path).permissions();
    EXPECT_EQ(perms & (std::filesystem::perms::group_all | std::filesystem::perms::others_all), std::filesystem::perms::none);
#endif
    std::filesystem::remove_all(dir);
}

#ifdef _WIN32
TEST(ProviderCredential, ReadHandleAllowsAtomicReplacementAndKeepsOldFileIdentity) {
    const auto dir = std::filesystem::temp_directory_path() /
                     ("pa-cred-open-reader-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(dir);
    const auto path = dir / "credential.bin";
    ASSERT_TRUE(pv::store_credential(path, "before-replacement").has_value());
    std::ifstream input(path, std::ios::binary);
    ASSERT_TRUE(input);
    const std::vector<char> before((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    input.close();

    HANDLE opened = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(opened, INVALID_HANDLE_VALUE);
    struct CloseHandleOnExit {
        HANDLE value;
        ~CloseHandleOnExit() { CloseHandle(value); }
    } close{opened};

    const auto replacement = pv::store_credential(path, "after-replacement");
    if (!replacement) EXPECT_EQ(replacement.error(), pv::CredentialError::ReplaceFailed);
    std::vector<char> from_open_handle(before.size());
    DWORD received = 0;
    ASSERT_TRUE(ReadFile(opened, from_open_handle.data(), static_cast<DWORD>(from_open_handle.size()), &received, nullptr));
    ASSERT_EQ(received, before.size());
    EXPECT_EQ(from_open_handle, before);
    const auto current = pv::load_credential(path);
    ASSERT_TRUE(current);
    EXPECT_EQ(current->view(), replacement ? "after-replacement" : "before-replacement");
    std::size_t temp_files = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        temp_files += entry.path().filename().string().starts_with("credential.bin.tmp.") ? 1 : 0;
    }
    EXPECT_EQ(temp_files, 0);
    std::cout << "read_handle_replace=" << (replacement ? "success" : "ReplaceFailed")
              << " open_handle=old-complete target=" << (replacement ? "new-complete" : "old-complete")
              << " temp_files=" << temp_files << '\n';
    std::filesystem::remove_all(dir);
}
#endif

TEST(ProviderCredential, ConcurrentStoresUseDistinctTemporaryFiles) {
    const auto dir = std::filesystem::temp_directory_path() /
                     ("pa-cred-concurrent-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(dir);
    const auto path = dir / "credential.bin";
    ASSERT_TRUE(pv::store_credential(path, "initial-token").has_value());
    std::atomic<int> successes{0};
    std::atomic<int> replacement_rejections{0};
    std::atomic<int> other_failures{0};
    std::atomic<bool> writing{true};
    std::atomic<bool> reader_started{false};
    std::atomic<int> complete_reads{0};
    std::atomic<int> unreadable_reads{0};
    std::atomic<int> partial_reads{0};
    std::thread reader([&] {
        reader_started = true;
        while (writing) {
            const auto current = pv::load_credential(path);
            if (current) {
                if (current->view() == "initial-token" || current->view().starts_with("credential-")) {
                    ++complete_reads;
                } else {
                    ++partial_reads;
                }
            } else if (current.error() == pv::CredentialError::Unreadable) {
                ++unreadable_reads;
            } else {
                ++partial_reads;
            }
            std::this_thread::yield();
        }
    });
    while (!reader_started) std::this_thread::yield();
    std::vector<std::thread> writers;
    for (int writer = 0; writer < 8; ++writer) {
        writers.emplace_back([&, writer] {
            for (int replacement = 0; replacement < 10; ++replacement) {
                const auto token = "credential-" + std::to_string(writer) + "-" + std::to_string(replacement);
                const auto stored = pv::store_credential(path, token);
                if (stored) {
                    ++successes;
                } else if (stored.error() == pv::CredentialError::ReplaceFailed) {
                    ++replacement_rejections;
                } else {
                    ++other_failures;
                }
            }
        });
    }
    for (auto& writer : writers) writer.join();
    writing = false;
    reader.join();
    EXPECT_EQ(successes + replacement_rejections + other_failures, 80);
    EXPECT_GT(successes, 0);
    EXPECT_EQ(other_failures, 0);
    EXPECT_GT(complete_reads, 0);
    EXPECT_EQ(partial_reads, 0);
    const auto read = pv::load_credential(path);
    ASSERT_TRUE(read.has_value());
    EXPECT_TRUE(read->view().starts_with("credential-"));
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        EXPECT_FALSE(entry.path().filename().string().starts_with("credential.bin.tmp."));
    }
    std::cout << "credential_store_successes=" << successes.load()
              << " replacement_rejections=" << replacement_rejections.load()
              << " other_failures=" << other_failures.load() << " complete_reads=" << complete_reads.load()
              << " unreadable_reads=" << unreadable_reads.load() << " partial_reads=" << partial_reads.load()
              << " final_file=complete temp_files=0\n";
#ifndef _WIN32
    const auto perms = std::filesystem::status(path).permissions();
    EXPECT_EQ(perms & (std::filesystem::perms::group_all | std::filesystem::perms::others_all), std::filesystem::perms::none);
#endif
    std::filesystem::remove_all(dir);
}

TEST(ProviderCredential, FailedReplacementKeepsExistingFile) {
    const auto dir = std::filesystem::temp_directory_path() /
                     ("pa-cred-failure-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(dir);
    const auto path = dir / "credential.bin";
    ASSERT_TRUE(pv::store_credential(path, "existing-token").has_value());
#ifdef _WIN32
    HANDLE opened = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(opened, INVALID_HANDLE_VALUE);
    const auto replacement = pv::store_credential(path, "replacement-token");
    ASSERT_FALSE(replacement.has_value());
    EXPECT_EQ(replacement.error(), pv::CredentialError::ReplaceFailed);
    CloseHandle(opened);
#else
    std::error_code ec;
    std::filesystem::permissions(dir, std::filesystem::perms::owner_read | std::filesystem::perms::owner_exec,
                                 std::filesystem::perm_options::replace, ec);
    ASSERT_FALSE(ec);
    EXPECT_FALSE(pv::store_credential(path, "replacement-token").has_value());
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
    ASSERT_FALSE(ec);
#endif
    const auto read = pv::load_credential(path);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->view(), "existing-token");
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        EXPECT_FALSE(entry.path().filename().string().starts_with("credential.bin.tmp."));
    }
    std::filesystem::remove_all(dir);
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
