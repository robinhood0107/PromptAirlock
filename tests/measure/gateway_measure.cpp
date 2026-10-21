// HTTP 로 끝까지 지연·처리량 측정(Phase 8a). 기관 앱(이 도구) → HTTPS 게이트웨이 → 탐지(NER 선택)·Vault → mock provider.
// 요청마다 TLS 연결을 새로 연다(게이트웨이 → mock 도 같다). 문장은 모두 합성이다.
//   gateway_measure [--no-ner] [--sequential N] [--clients C] [--per-client K]
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <vector>

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
using Clock = std::chrono::steady_clock;

const std::string short_prompt = "한빛시청 김민준 주무관에게 010-2345-6789 로 다음 주 회의 일정을 알려 주세요.";

// 약 1 KB 문단(이름·전화·이메일 섞임)
std::string long_prompt() {
    std::string text;
    for (int i = 0; i < 6; ++i) {
        text += "지난 회의에서 이서연 주무관이 user" + std::to_string(i) +
                "@example.invalid 로 보낸 자료를 검토했고, 다음 단계는 박지훈 팀장과 정리하기로 했습니다. ";
    }
    return text;
}

struct Stats {
    std::vector<double> ms;
    int errors = 0;
};

void report(const char* name, Stats stats) {
    std::ranges::sort(stats.ms);
    const auto at = [&](double q) {
        if (stats.ms.empty()) {
            return 0.0;
        }
        const auto index = static_cast<std::size_t>(q * static_cast<double>(stats.ms.size() - 1) + 0.5);
        return stats.ms[std::min(index, stats.ms.size() - 1)];
    };
    std::printf("%-40s p50 %9.3f  p95 %9.3f  max %9.3f  (n=%zu, errors %d)\n", name, at(0.5), at(0.95), at(1.0),
                stats.ms.size(), stats.errors);
}

class Rig {
public:
    explicit Rig(bool with_ner) {
        cert_ = pa_test::make_test_certificate();
        server_tls_.emplace(std::move(*prompt_airlock::tls::make_server_context(cert_.certificate_pem, cert_.private_key_pem)));
        client_tls_.emplace(std::move(*prompt_airlock::tls::make_client_context(std::string_view{cert_.certificate_pem})));
        std::shared_ptr<const prompt_airlock::detect::NerScanner> ner;
        if (with_ner) {
            auto pool = prompt_airlock::ner::NerPool::make(PA_NER_MODEL_DIR);
            if (!pool) {
                std::fputs("NER model files are missing\n", stderr);
                std::exit(1);
            }
            ner = *pool;
        }
        const std::string_view terms[] = {"한빛시청"};
        detectors_.emplace(std::move(*prompt_airlock::detect::Detectors::make(terms, ner)));
        prompt_airlock::vault_client::ServiceOptions options;
        options.exe = PA_VAULT_EXE;
        vault_.emplace(options);
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
        // 실행 파일과 같은 io 스레드 4개
        for (int i = 0; i < 4; ++i) {
            threads_.emplace_back([this] { io_.run(); });
        }
    }

    ~Rig() {
        server_->stop();
        mock_->stop();
        for (auto& t : threads_) {
            t.join();
        }
    }

    // 요청 하나의 왕복 시간(ms). 200 이 아니면 nullopt.
    std::optional<double> once(const std::string& text) {
        const auto start = Clock::now();
        try {
            asio::io_context io;
            beast::ssl_stream<beast::tcp_stream> stream(io, *client_tls_);
            SSL_set1_host(stream.native_handle(), "localhost");
            beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(60));
            beast::get_lowest_layer(stream).connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"),
                                                                  server_->local_endpoint().port()));
            stream.handshake(asio::ssl::stream_base::client);
            http::request<http::string_body> req{http::verb::post, "/v1/chat/completions", 11};
            req.set(http::field::host, "localhost");
            req.set(http::field::content_type, "application/json");
            req.set(http::field::authorization, "Bearer desk-token");
            req.body() =
                json{{"model", "any"}, {"messages", json::array({{{"role", "user"}, {"content", text}}})}}.dump();
            req.prepare_payload();
            http::write(stream, req);
            beast::flat_buffer buffer;
            http::response<http::string_body> res;
            http::read(stream, buffer, res);
            if (res.result_int() != 200) {
                return std::nullopt;
            }
        } catch (const std::exception&) {
            return std::nullopt;
        }
        return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
    }

private:
    static std::string hash_of(std::string_view token) {
        return core::sha256_hex(std::as_bytes(std::span(token.data(), token.size())));
    }

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
    std::vector<std::thread> threads_;
};

Stats sequential(Rig& rig, const std::string& text, int n) {
    Stats stats;
    for (int i = 0; i < n; ++i) {
        if (const auto ms = rig.once(text)) {
            stats.ms.push_back(*ms);
        } else {
            ++stats.errors;
        }
    }
    return stats;
}

}  // namespace

int main(int argc, char** argv) {
    bool with_ner = true;
    int n = 200;
    int clients = 8;
    int per_client = 25;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--no-ner") {
            with_ner = false;
        } else if (arg == "--sequential" && i + 1 < argc) {
            n = std::atoi(argv[++i]);
        } else if (arg == "--clients" && i + 1 < argc) {
            clients = std::atoi(argv[++i]);
        } else if (arg == "--per-client" && i + 1 < argc) {
            per_client = std::atoi(argv[++i]);
        }
    }
    std::printf("ner: %s, gateway io threads 4, sequential %d, clients %d x %d\n", with_ner ? "on" : "off", n, clients,
                per_client);
    Rig rig(with_ner);
    const std::string paragraph = long_prompt();
    std::string page;  // 4 KiB 안팎(성능 목표의 질문 크기)
    while (page.size() + paragraph.size() <= 4096) {
        page += paragraph;
    }
    std::printf("short prompt bytes %zu, long prompt bytes %zu, page prompt bytes %zu\n", short_prompt.size(),
                paragraph.size(), page.size());
    (void)sequential(rig, short_prompt, 10);  // 준비 운동(Vault 첫 기동, 모델 첫 실행)

    report("sequential short (ms)", sequential(rig, short_prompt, n));
    report("sequential long ~1KB (ms)", sequential(rig, paragraph, n));
    report("sequential page ~4KB (ms)", sequential(rig, page, n));

    Stats concurrent;
    std::mutex mutex;
    const auto start = Clock::now();
    {
        std::vector<std::jthread> workers;
        for (int c = 0; c < clients; ++c) {
            workers.emplace_back([&] {
                Stats local = sequential(rig, short_prompt, per_client);
                std::scoped_lock lock(mutex);
                concurrent.ms.insert(concurrent.ms.end(), local.ms.begin(), local.ms.end());
                concurrent.errors += local.errors;
            });
        }
    }
    const double seconds = std::chrono::duration<double>(Clock::now() - start).count();
    report("concurrent short (ms)", concurrent);
    std::printf("%-40s %9.1f\n", "throughput (requests/s)",
                static_cast<double>(concurrent.ms.size()) / seconds);
    return 0;
}
