// HTTP 로 끝까지 지연·처리량 측정(Phase 8a, 9-3). 기관 앱(이 도구) → HTTPS 게이트웨이 → 탐지(NER 선택)·Vault → mock provider.
// 요청마다 TLS 연결을 새로 연다(게이트웨이 → mock 도 같다). 문장은 모두 합성이다.
// 순차 측정은 왕복 시간과 함께 처리 단계(Pipeline::handle) 시간, provider 호출 시간, 그 차(provider 제외 처리 시간)를 낸다.
// 과부하 구간은 처리 중 요청 상한보다 많이 동시에 보내 응답 상태를 센다. 끝에 provider 가 받은 본문에 원문 값이 있는지 센다.
//   gateway_measure [--no-ner] [--sequential N] [--clients C] [--per-client K]
//                   [--overload-clients C] [--overload-per-client K]
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
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
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "mock_provider.hpp"
#include "prompt_airlock/core/sha256.hpp"
#include "prompt_airlock/detect/view.hpp"
#include "prompt_airlock/gateway/pipeline.hpp"
#include "prompt_airlock/gateway/server.hpp"
#include "prompt_airlock/ner/pool.hpp"
#include "prompt_airlock/ner/tokenizer.hpp"
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

// 문단의 i 번째 문장(이름·이메일 섞임)
std::string paragraph_sentence(int i) {
    return "지난 회의에서 이서연 주무관이 user" + std::to_string(i) +
           "@example.invalid 로 보낸 자료를 검토했고, 다음 단계는 박지훈 팀장과 정리하기로 했습니다. ";
}

// 약 1 KB 문단
std::string long_prompt() {
    std::string text;
    for (int i = 0; i < 6; ++i) {
        text += paragraph_sentence(i);
    }
    return text;
}

// provider 로 나가면 안 되는 원문 값(결정론 규칙이 늘 잡는 전화·이메일). 받은 본문에서 센다.
const std::vector<std::string> raw_values = {"010-2345-6789", "example.invalid"};

struct Stats {
    std::vector<double> ms;
    int errors = 0;
    std::map<std::string, int> reasons;  // 오류의 상태와 사유("502 provider_error", "0 system 10014" 처럼)
};

void report(const std::string& name, Stats stats) {
    std::ranges::sort(stats.ms);
    const auto at = [&](double q) {
        if (stats.ms.empty()) {
            return 0.0;
        }
        const auto index = static_cast<std::size_t>(q * static_cast<double>(stats.ms.size() - 1) + 0.5);
        return stats.ms[std::min(index, stats.ms.size() - 1)];
    };
    std::printf("%-44s p50 %9.3f  p95 %9.3f  max %9.3f  (n=%zu, errors %d)\n", name.c_str(), at(0.5), at(0.95),
                at(1.0), stats.ms.size(), stats.errors);
    for (const auto& [reason, count] : stats.reasons) {
        std::printf("%-44s %d\n", ("  error " + reason).c_str(), count);
    }
}

// 여러 스레드가 시간을 적는 곳. 순차 측정에서는 요청 순서대로 쌓인다.
class Timings {
public:
    void add(Clock::time_point start) {
        const double ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        std::scoped_lock lock(mutex_);
        ms_.push_back(ms);
    }
    std::vector<double> take() {
        std::scoped_lock lock(mutex_);
        return std::exchange(ms_, {});
    }

private:
    std::mutex mutex_;
    std::vector<double> ms_;
};

// 모델 tokenizer 로 센 token 수(앞뒤 special 2개 포함, NER 창 한도 256 과 같은 기준).
std::size_t token_count(const prompt_airlock::ner::WordPieceTokenizer& tokenizer, const std::string& text) {
    const auto view = prompt_airlock::detect::make_view(text);
    return view ? tokenizer.encode(view->units).size() : 0;
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
            [this](std::string body) -> asio::awaitable<std::expected<gw::ProviderReply, gw::ProviderError>> {
                const auto start = Clock::now();
                auto reply = co_await provider_->send(std::move(body));
                provider_ms.add(start);
                co_return reply;
            },
            core::OutputTokenCap::standard(), "demo-alias", work_.get_executor());
        server_.emplace(io_, *server_tls_, loopback, auth_,
                        [this](gw::AcceptedRequest request) -> asio::awaitable<gw::JsonResponse> {
                            const auto start = Clock::now();
                            auto reply = co_await pipeline_->handle(std::move(request));
                            handle_ms.add(start);
                            co_return reply;
                        });
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

    struct Reply {
        unsigned status = 0;  // 0 은 연결·읽기 실패
        std::string code;     // 200 이 아닐 때 오류 사유, 상태 0 이면 소켓 오류 번호
        double ms = 0;
    };

    // 요청 하나의 왕복.
    Reply call(const std::string& text) {
        Reply reply;
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
            reply.status = res.result_int();
            if (reply.status != 200) {
                const auto body = json::parse(res.body(), nullptr, false);
                if (body.is_object() && body.contains("error")) {
                    reply.code = body["error"].value("code", "");
                }
            }
        } catch (const boost::system::system_error& e) {
            reply.status = 0;
            reply.code = "system " + std::to_string(e.code().value());  // 10014 는 이 PC 의 소켓 오류(#118)
        } catch (const std::exception&) {
            reply.status = 0;
            reply.code = "exception";
        }
        reply.ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        return reply;
    }

    // provider 가 받은 본문 수와, 원문 값이 든 본문 수.
    std::pair<std::size_t, std::size_t> egress_check() const {
        const auto bodies = mock_->received();
        const auto leaked = std::ranges::count_if(bodies, [](const std::string& body) {
            return std::ranges::any_of(raw_values,
                                       [&](const std::string& raw) { return body.find(raw) != std::string::npos; });
        });
        return {bodies.size(), static_cast<std::size_t>(leaked)};
    }

    Timings handle_ms;    // Pipeline::handle 전체
    Timings provider_ms;  // 그 안의 provider 호출

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
    asio::thread_pool work_{gw::pipeline_work_threads};
    std::optional<pa_mock::MockProvider> mock_;
    std::optional<prompt_airlock::provider::HttpsClient> provider_;
    std::optional<gw::Pipeline> pipeline_;
    std::optional<gw::Server> server_;
    std::vector<std::thread> threads_;
};

Stats sequential(Rig& rig, const std::string& text, int n) {
    Stats stats;
    for (int i = 0; i < n; ++i) {
        const auto reply = rig.call(text);
        if (reply.status == 200) {
            stats.ms.push_back(reply.ms);
        } else {
            ++stats.errors;
            ++stats.reasons[std::to_string(reply.status) + " " + reply.code];
        }
    }
    return stats;
}

// 순차 n 회: 왕복, 처리 단계, provider, 처리 단계 - provider. 요청이 하나씩이라 두 시간이 같은 순서로 짝지어진다.
void measure_sequential(Rig& rig, const std::string& name, const std::string& text, int n) {
    (void)rig.handle_ms.take();
    (void)rig.provider_ms.take();
    const auto round_trip = sequential(rig, text, n);
    const auto handle = rig.handle_ms.take();
    const auto provider = rig.provider_ms.take();
    report(name + " round trip (ms)", round_trip);
    report(name + " handle (ms)", Stats{handle, 0, {}});
    report(name + " provider (ms)", Stats{provider, 0, {}});
    if (handle.size() != provider.size()) {
        std::printf("%-44s handle %zu, provider %zu: not paired\n", (name + " gateway").c_str(), handle.size(),
                    provider.size());
        return;
    }
    Stats gateway;
    for (std::size_t i = 0; i < handle.size(); ++i) {
        gateway.ms.push_back(handle[i] - provider[i]);
    }
    report(name + " gateway = handle - provider (ms)", gateway);
}

int run(int argc, char** argv) {
    bool with_ner = true;
    int n = 200;
    int clients = 8;
    int per_client = 25;
    int overload_clients = 32;
    int overload_per_client = 10;
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
        } else if (arg == "--overload-clients" && i + 1 < argc) {
            overload_clients = std::atoi(argv[++i]);
        } else if (arg == "--overload-per-client" && i + 1 < argc) {
            overload_per_client = std::atoi(argv[++i]);
        }
    }
    std::printf("ner: %s, gateway io threads 4, work threads %u, in-flight limit %zu, request time limit %lld s\n",
                with_ner ? "on" : "off", gw::pipeline_work_threads, gw::pipeline_in_flight_limit,
                static_cast<long long>(gw::request_time_limit.count()));
    std::printf("sequential %d, clients %d x %d, overload clients %d x %d\n", n, clients, per_client, overload_clients,
                overload_per_client);
    const auto tokenizer =
        prompt_airlock::ner::WordPieceTokenizer::load(std::filesystem::path(PA_NER_MODEL_DIR) / "tokenizer.json");
    if (!tokenizer) {
        std::fputs("tokenizer.json is missing\n", stderr);
        return 1;
    }
    Rig rig(with_ner);
    const std::string paragraph = long_prompt();
    std::string page;  // 4 KiB 안팎(성능 목표의 질문 크기)
    while (page.size() + paragraph.size() <= 4096) {
        page += paragraph;
    }
    // 목표 2 의 조건(256 token 이하)에 맞춘 질문: 문단의 문장을 256 token 을 넘기 직전까지 붙인다.
    std::string fit256;
    for (int i = 0;; ++i) {
        const std::string next = fit256 + paragraph_sentence(i);
        if (token_count(*tokenizer, next) > 256) {
            break;
        }
        fit256 = next;
    }
    std::printf("prompt bytes / tokens: short %zu / %zu, fit256 %zu / %zu, long %zu / %zu, page %zu / %zu\n",
                short_prompt.size(), token_count(*tokenizer, short_prompt), fit256.size(),
                token_count(*tokenizer, fit256), paragraph.size(), token_count(*tokenizer, paragraph), page.size(),
                token_count(*tokenizer, page));
    (void)sequential(rig, short_prompt, 10);  // 준비 운동(Vault 첫 기동, 모델 첫 실행)

    measure_sequential(rig, "short", short_prompt, n);
    measure_sequential(rig, "fit256", fit256, n);
    measure_sequential(rig, "long ~1KB", paragraph, n);
    measure_sequential(rig, "page ~4KB", page, n);

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
                for (const auto& [reason, count] : local.reasons) {
                    concurrent.reasons[reason] += count;
                }
            });
        }
    }
    const double seconds = std::chrono::duration<double>(Clock::now() - start).count();
    report("concurrent short (ms)", concurrent);
    std::printf("%-44s %9.1f\n", "throughput (requests/s)", static_cast<double>(concurrent.ms.size()) / seconds);

    // 과부하 구간: 상한보다 많은 동시 요청(4 KiB 질문, NER 이 가장 오래 걸리는 조건)의 응답 상태를 센다.
    std::map<std::string, int> outcomes;  // "200", "503 overloaded" 처럼
    Stats accepted;
    const auto overload_start = Clock::now();
    {
        std::vector<std::jthread> workers;
        for (int c = 0; c < overload_clients; ++c) {
            workers.emplace_back([&] {
                for (int k = 0; k < overload_per_client; ++k) {
                    const auto reply = rig.call(page);
                    std::scoped_lock lock(mutex);
                    ++outcomes[std::to_string(reply.status) + (reply.code.empty() ? "" : " " + reply.code)];
                    if (reply.status == 200) {
                        accepted.ms.push_back(reply.ms);
                    }
                }
            });
        }
    }
    const double overload_seconds = std::chrono::duration<double>(Clock::now() - overload_start).count();
    for (const auto& [outcome, count] : outcomes) {
        std::printf("%-44s %d\n", ("overload status " + outcome).c_str(), count);
    }
    report("overload accepted round trip (ms)", accepted);
    std::printf("%-44s %9.1f\n", "overload seconds", overload_seconds);

    const auto [bodies, leaked] = rig.egress_check();
    std::printf("%-44s %zu bodies, %zu with raw values\n", "provider egress", bodies, leaked);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    // 띄우기 실패(listen 등)는 예외로 온다. 프로세스를 강제 종료시키지 않고 이유를 남긴다.
    try {
        return run(argc, argv);
    } catch (const std::exception& e) {
        std::fflush(stdout);
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return 2;
    }
}
