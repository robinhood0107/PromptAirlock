// Drogon 으로 같은 HTTPS mock 시나리오를 구성해 Beast 와 구현량·제어 방식을 비교한다.
// drogon::app() 은 프로세스 전역 단일 객체라 한 프로세스에서 한 번만 실행할 수 있다. 시나리오를 한 테스트에 모은다.
#include "test_cert.hpp"

#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <drogon/drogon.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <thread>

namespace {

unsigned short free_port() {
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor a(io, {boost::asio::ip::make_address("127.0.0.1"), 0});
    return a.local_endpoint().port();
}

// Drogon 서버는 인증서·키를 파일 경로로만 받는다. 테스트 임시 디렉터리에 쓰고 끝나면 지운다.
struct TempPem {
    std::filesystem::path dir;
    std::filesystem::path cert;
    std::filesystem::path key;
    explicit TempPem(const pa_spike::TestCert& c) {
        dir = std::filesystem::temp_directory_path() / ("pa-drogon-" + std::to_string(std::random_device{}()));
        std::filesystem::create_directories(dir);
        cert = dir / "cert.pem";
        key = dir / "key.pem";
        std::ofstream(cert, std::ios::binary) << c.cert_pem;
        std::ofstream(key, std::ios::binary) << c.key_pem;
    }
    ~TempPem() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

}  // namespace

TEST(DrogonHttps, ServerAndClientScenarios) {
    auto made = pa_spike::make_test_cert();
    ASSERT_TRUE(made.has_value());
    TempPem pem(*made);
    const auto port = free_port();

    drogon::app().setThreadNum(1).setLogLevel(trantor::Logger::kWarn);
    drogon::app().addListener("127.0.0.1", port, true, pem.cert.string(), pem.key.string());
    drogon::app().registerHandler(
        "/v1/mock",
        [](const drogon::HttpRequestPtr& req, std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
            auto res = drogon::HttpResponse::newHttpResponse();
            res->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            res->setBody(R"({"status":"ok","echo":")" + std::string(req->path()) + R"("})");
            cb(res);
        },
        {drogon::Get});
    drogon::app().registerHandler(
        "/v1/stall",
        [](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& cb) {
            // 응답을 1초 늦춰 클라이언트 timeout 을 유도한다.
            drogon::app().getLoop()->runAfter(1.0, [cb = std::move(cb)] { cb(drogon::HttpResponse::newHttpResponse()); });
        },
        {drogon::Get});

    std::thread server([] { drogon::app().run(); });
    while (!drogon::app().isRunning()) std::this_thread::yield();

    const std::string base = "https://localhost:" + std::to_string(port);

    // 1) 사설 CA 를 신뢰하도록 설정한 클라이언트: OpenSSL SSL_CONF 명령으로 CA 파일 지정.
    {
        auto client = drogon::HttpClient::newHttpClient(base, nullptr, false, true);
        client->addSSLConfigs({{"VerifyCAFile", pem.cert.string()}});
        auto req = drogon::HttpRequest::newHttpRequest();
        req->setPath("/v1/mock");
        auto [result, res] = client->sendRequest(req, 3.0);
        RecordProperty("custom_ca_result", drogon::to_string_view(result).data());
        EXPECT_EQ(result, drogon::ReqResult::Ok);
        if (res) {
            EXPECT_EQ(res->statusCode(), drogon::k200OK);
            EXPECT_EQ(std::string(res->body()), R"({"status":"ok","echo":"/v1/mock"})");
        }
    }
    // 2) 기본 신뢰 저장소만 쓰는 클라이언트는 자체 서명 인증서를 거부해야 한다.
    {
        auto client = drogon::HttpClient::newHttpClient(base, nullptr, false, true);
        auto req = drogon::HttpRequest::newHttpRequest();
        req->setPath("/v1/mock");
        auto [result, res] = client->sendRequest(req, 3.0);
        EXPECT_NE(result, drogon::ReqResult::Ok);
    }
    // 3) 응답 지연 시 timeout.
    {
        auto client = drogon::HttpClient::newHttpClient(base, nullptr, false, true);
        client->addSSLConfigs({{"VerifyCAFile", pem.cert.string()}});
        auto req = drogon::HttpRequest::newHttpRequest();
        req->setPath("/v1/stall");
        auto [result, res] = client->sendRequest(req, 0.2);
        EXPECT_EQ(result, drogon::ReqResult::Timeout);
    }

    drogon::app().getLoop()->queueInLoop([] { drogon::app().quit(); });
    server.join();
}
