// 게이트웨이 실행 파일.
//   prompt-airlock serve <config.json>      설정 하나로 Vault, NER pool, HTTPS 서버를 띄운다
//   prompt-airlock issue-token <origin>      출처 token 을 발급한다(원문은 이때 한 번만 출력, 설정에는 해시만)
//   prompt-airlock keys add|list|revoke <config.json> ...  설정 파일의 출처 키를 관리한다
//   prompt-airlock policy suggest <폴더>         기관 대상어 후보를 로컬에서 제안한다
//   prompt-airlock protect-credential <평문 파일|-> <출력 파일>   provider 자격 증명을 보호 저장한다(Windows DPAPI, Linux 0600).
//                                       - 는 표준 입력. 실행 중인 게이트웨이는 다음 요청부터 새 값을 쓴다(ADR 0026)
//   prompt-airlock audit verify|list <감사 폴더> [줄 수]       감사 기록을 로컬에서 검증·열람한다(관리 기록은 admin/ 에)
#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/use_future.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <exception>
#include <expected>
#include <filesystem>
#include <future>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "prompt_airlock/audit/log.hpp"
#include "prompt_airlock/core/document.hpp"
#include "prompt_airlock/core/sha256.hpp"
#include "prompt_airlock/core/sensitive.hpp"
#include "prompt_airlock/core/utf8.hpp"
#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/extract/runner.hpp"
#include "prompt_airlock/gateway/auth.hpp"
#include "prompt_airlock/gateway/config.hpp"
#include "prompt_airlock/gateway/documents.hpp"
#include "prompt_airlock/gateway/pipeline.hpp"
#include "prompt_airlock/gateway/request_json.hpp"
#include "prompt_airlock/gateway/server.hpp"
#include "prompt_airlock/ner/pool.hpp"
#include "prompt_airlock/ner/sentence_classifier.hpp"
#include "prompt_airlock/provider/cli_client.hpp"
#include "prompt_airlock/provider/https_client.hpp"
#include "prompt_airlock/tls/context.hpp"
#include "prompt_airlock/vault_client/service.hpp"

namespace {

namespace asio = boost::asio;
namespace audit = prompt_airlock::audit;
namespace core = prompt_airlock::core;
namespace detect = prompt_airlock::detect;
namespace extract = prompt_airlock::extract;
namespace gw = prompt_airlock::gateway;

struct RuntimePaths {
    std::filesystem::path vault_executable;
    std::filesystem::path ner_model_dir;
    std::filesystem::path sentence_model_dir;
};

std::expected<RuntimePaths, const char*> runtime_paths() {
    const auto development_paths = []() -> std::expected<RuntimePaths, const char*> {
        RuntimePaths paths{PA_VAULT_EXE, PA_NER_MODEL_DIR, PA_SENTENCE_MODEL_DIR};
        if (paths.vault_executable.empty() || paths.ner_model_dir.empty() || paths.sentence_model_dir.empty() ||
            !paths.vault_executable.is_absolute() || !paths.ner_model_dir.is_absolute() ||
            !paths.sentence_model_dir.is_absolute()) {
            return std::unexpected("build_paths_invalid");
        }
        return paths;
    };

    const auto extractor = extract::default_executable();
    if (extractor.empty()) {
        return development_paths();
    }
    const auto bin_dir = extractor.parent_path();
    if (bin_dir.empty() || bin_dir.filename() != std::filesystem::path("bin")) {
        return development_paths();
    }
    const auto root = bin_dir.parent_path();
    if (root.empty() || !root.is_absolute()) {
        return std::unexpected("bundle_path_invalid");
    }

    std::error_code error;
    const auto manifest = root / "manifest.sha256";
    const auto manifest_status = std::filesystem::symlink_status(manifest, error);
    if (error) {
        return std::unexpected("bundle_probe_failed");
    }
    if (manifest_status.type() == std::filesystem::file_type::not_found) {
        return std::unexpected("bundle_manifest_missing");
    }
    if (manifest_status.type() != std::filesystem::file_type::regular) {
        return std::unexpected("bundle_invalid");
    }

#ifdef _WIN32
    const auto vault = root / "libexec" / "prompt-airlock-vault.exe";
#else
    const auto vault = root / "libexec" / "prompt-airlock-vault";
#endif
    const auto ner_dir = root / "share" / "models" / "ner";
    const auto is_regular_file = [&error](const std::filesystem::path& path) {
        error.clear();
        const auto status = std::filesystem::symlink_status(path, error);
        return !error && status.type() == std::filesystem::file_type::regular;
    };
    if (!is_regular_file(extractor) || !is_regular_file(vault) ||
        !is_regular_file(ner_dir / "config.json") || !is_regular_file(ner_dir / "tokenizer.json") ||
        !is_regular_file(ner_dir / "model.onnx")) {
        return std::unexpected("bundle_incomplete");
    }

    return RuntimePaths{vault, ner_dir, root / "share" / "models" / "sentence"};
}

// 요청을 처리하는 io 스레드 수. 탐지·Vault 호출이 동기라 동시 처리 수의 상한이기도 하다.
constexpr unsigned io_threads = 4;

std::optional<std::string> read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

int fail(const char* what) {
    std::fprintf(stderr, "prompt-airlock: %s\n", what);
    return 1;
}

struct Tls {
    asio::ssl::context server;  // 게이트웨이 입구
    asio::ssl::context client;  // provider 연결
    std::optional<int> cert_days;
};

// 입구 인증서·키와 provider 신뢰 저장소를 읽는다. 실패하면 기동 실패 문구.
std::expected<Tls, const char*> load_tls(const gw::Config& config) {
    const auto cert = read_file(config.listen.certificate_chain);
    const auto key = read_file(config.listen.private_key);
    if (!cert || !key) {
        return std::unexpected("cannot read the listen certificate or key");
    }
    auto server = prompt_airlock::tls::make_server_context(*cert, *key);
    if (!server) {
        return std::unexpected("listen certificate or key rejected (weak key, bad PEM or mismatched pair)");
    }
    std::optional<std::string> trust;
    if (!config.provider.trust_file.empty() && !(trust = read_file(config.provider.trust_file))) {
        return std::unexpected("cannot read the provider trust file");
    }
    auto client =
        prompt_airlock::tls::make_client_context(trust ? std::optional<std::string_view>(*trust) : std::nullopt);
    if (!client) {
        return std::unexpected("provider trust store rejected");
    }
    return Tls{std::move(*server), std::move(*client), prompt_airlock::tls::certificate_days_left(*cert)};
}

// 경고 모드(ADR 0023): 켰는데 판별기를 불러오지 못하면 기동하지 않는다(판별 없이 보내지 않는다). 끄면 빈 함수.
std::expected<gw::SentenceCheck, const char*> make_sentence_check(bool enabled,
                                                                  const std::filesystem::path& model_dir) {
    if (!enabled) {
        return gw::SentenceCheck{};
    }
    auto classifier = prompt_airlock::ner::SentenceClassifier::make(model_dir);
    if (!classifier) {
        return std::unexpected("sentence classifier files are missing or do not match the pinned hashes");
    }
    return [classifier = *classifier](std::string_view text, bool named_person, std::stop_token stop)
               -> std::expected<std::optional<std::string>, core::DetectError> {
        auto hit = classifier->classify(text, named_person, stop);
        if (!hit) {
            using prompt_airlock::ner::SentenceError;
            return std::unexpected(hit.error() == SentenceError::Overloaded ? core::DetectError::Overloaded
                                   : hit.error() == SentenceError::Timeout  ? core::DetectError::Timeout
                                                                            : core::DetectError::Unavailable);
        }
        if (!*hit) {
            return std::nullopt;
        }
        return (*hit)->category;
    };
}

int check_failure(const char* stage, const char* code) noexcept {
    std::fprintf(stderr, "check: failed stage=%s code=%s\n", stage, code);
    return 1;
}

// 주소나 인증서 세부 사항을 드러내지 않는 연결 오류 코드.
const char* connection_check_code(prompt_airlock::provider::ConnectCheckError error) noexcept {
    using prompt_airlock::provider::ConnectCheckError;
    switch (error) {
        case ConnectCheckError::ResolveFailed: return "resolve_failed";
        case ConnectCheckError::ConnectFailed: return "connect_failed";
        case ConnectCheckError::Timeout: return "timeout";
        case ConnectCheckError::TlsSetupFailed: return "tls_setup_failed";
        case ConnectCheckError::TlsHandshakeFailed: return "tls_handshake_failed";
    }
    return "connect_failed";
}

// 기본은 요청·감사·provider 실행 없이 로컬 준비만 확인한다. --connect만 TCP/TLS handshake를 추가한다.
int check_command(std::string_view config_arg, bool connect_requested = false) noexcept {
    try {
        const std::filesystem::path config_path(config_arg);
        const auto text = read_file(config_path);
        if (!text) {
            return check_failure("config", "unreadable");
        }
        const auto config = gw::parse_config(*text, config_path.parent_path());
        if (!config) {
            return check_failure("config", "invalid");
        }

        auto tls = load_tls(*config);
        if (!tls) {
            return check_failure("tls", "not_ready");
        }

        const bool local_cli = config->provider.protocol == gw::ProviderProtocol::LocalCliText;
        if (local_cli) {
            std::error_code ec;
            if (!std::filesystem::is_regular_file(config->provider.cli.executable, ec) || ec) {
                return check_failure("provider", "cli_executable_unavailable");
            }
        } else {
            const auto credential = prompt_airlock::provider::load_credential(config->provider.credential_file);
            if (!credential) {
                return check_failure("provider", "credential_unavailable");
            }
        }

        const auto paths = runtime_paths();
        if (!paths) {
            return check_failure("runtime", paths.error());
        }
        auto ner = prompt_airlock::ner::NerPool::make(paths->ner_model_dir);
        if (!ner) {
            return check_failure("model", "ner_unavailable");
        }
        auto sentence = make_sentence_check(config->sentence_warn, paths->sentence_model_dir);
        if (!sentence) {
            return check_failure("model", "sentence_unavailable");
        }

        const std::vector<std::string_view> terms(config->internal_terms.begin(), config->internal_terms.end());
        const auto detectors = prompt_airlock::detect::Detectors::make(terms, *ner, config->policy);
        if (!detectors) {
            return check_failure("policy", "invalid");
        }

        {
            prompt_airlock::vault_client::ServiceOptions vault_options;
            vault_options.exe = paths->vault_executable;
            prompt_airlock::vault_client::VaultService vault(vault_options);
            {
                auto scope = vault.open_scope();
                if (!scope) {
                    return check_failure("vault", "unavailable");
                }
            }
        }

        if (connect_requested && !local_cli) {
            prompt_airlock::provider::Endpoint endpoint{config->provider.host, config->provider.port,
                                                        config->provider.target, config->provider.credential_mode,
                                                        config->provider.api_version_header_name,
                                                        config->provider.api_version_header_value};
            prompt_airlock::provider::ClientLimits limits{std::chrono::seconds{5}};
            prompt_airlock::provider::HttpsClient client(tls->client, std::move(endpoint),
                                                          config->provider.credential_file, limits);
            asio::io_context connect_io;
            auto future = asio::co_spawn(connect_io, client.check_connection(), asio::use_future);
            connect_io.run();
            const auto connected = future.get();
            if (!connected) {
                return check_failure("provider_connection", connection_check_code(connected.error()));
            }
        }

        std::puts("check: ok");
        std::puts("config: ready");
        std::puts("tls: ready");
        std::puts("models: ready");
        std::puts("policy: ready");
        std::puts("vault: ready");
        std::puts("vault_scope: opened_and_dropped");
        std::puts("listener: not_started");
        std::puts("audit: not_opened");
        std::puts(local_cli ? "provider: local_cli_configuration_only" : "provider: https_configuration_only");
        if (local_cli) {
            std::puts("provider_invocation: not_tested");
            if (connect_requested) std::puts("provider_connection: not_tested");
        } else {
            std::puts(connect_requested ? "provider_connection: tls_verified" : "provider_connection: not_tested");
        }
        std::puts("provider_request: not_sent");
        std::puts("provider_transfer: not_tested");
        return 0;
    } catch (...) {
        return check_failure("internal", "check_failed");
    }
}

int stats_failure(audit::StatsStage stage, audit::AuditError error) noexcept {
    const auto stage_name = audit::stats_stage_name(stage);
    const auto code = audit::audit_error_name(error);
    std::fprintf(stderr, "stats: failed stage=%.*s code=%.*s\n",
                 static_cast<int>(stage_name.size()), stage_name.data(),
                 static_cast<int>(code.size()), code.data());
    return 1;
}

int stats_command(std::string_view audit_dir_arg) noexcept {
    try {
        const std::filesystem::path audit_dir(audit_dir_arg);
        const auto report = audit::AuditLog::stats_recent_readonly(audit_dir);
        if (!report) {
            return stats_failure(report.error().stage, report.error().error);
        }
        if (report->state == audit::StatsState::Missing) {
            std::puts("stats: state=missing scope=none");
            return 0;
        }
        if (report->state == audit::StatsState::Empty) {
            std::puts("stats: state=empty scope=none requests=0 normal=0 blocked=0 confirmation=0 failure=0");
            return 0;
        }
        if (report->state == audit::StatsState::Partial || !report->complete) {
            std::fputs("stats: failed state=partial scope=recent_24h_limited stage=read code=range_limited\n", stderr);
            return 1;
        }
        std::printf("stats: state=ok scope=recent_24h coverage=complete requests=%llu normal=%llu "
                    "blocked=%llu confirmation=%llu failure=%llu\n",
                    static_cast<unsigned long long>(report->requests),
                    static_cast<unsigned long long>(report->normal),
                    static_cast<unsigned long long>(report->blocked),
                    static_cast<unsigned long long>(report->confirmation),
                    static_cast<unsigned long long>(report->failure));
        return 0;
    } catch (...) {
        std::fputs("stats: failed stage=read code=internal_error\n", stderr);
        return 1;
    }
}

int serve(const std::filesystem::path& config_path) {
    const auto text = read_file(config_path);
    if (!text) {
        return fail("cannot read the config file");
    }
    const auto config = gw::parse_config(*text, config_path.parent_path());
    if (!config) {
        std::fprintf(stderr, "prompt-airlock: config rejected: %s at '%s'\n",
                     std::string(gw::config_problem_name(config.error().problem)).c_str(), config.error().field.c_str());
        return 1;
    }
    auto tls = load_tls(*config);
    if (!tls) {
        return fail(tls.error());
    }
    // 기동 때 한 번 읽어 설정 실수를 바로 알린다. 실행 중에는 요청마다 다시 읽는다(ADR 0026).
    if (config->provider.protocol != gw::ProviderProtocol::LocalCliText &&
        !prompt_airlock::provider::load_credential(config->provider.credential_file)) {
        return fail("provider credential file is missing, empty or has invalid characters");
    }

    const auto paths = runtime_paths();
    if (!paths) {
        return fail(paths.error());
    }
    auto ner = prompt_airlock::ner::NerPool::make(paths->ner_model_dir);
    if (!ner) {
        return fail("NER model files are missing or do not match the pinned hashes");
    }
    auto sentence = make_sentence_check(config->sentence_warn, paths->sentence_model_dir);
    if (!sentence) {
        return fail(sentence.error());
    }
    std::vector<std::string_view> terms(config->internal_terms.begin(), config->internal_terms.end());
    auto detectors = prompt_airlock::detect::Detectors::make(terms, *ner, config->policy);
    if (!detectors) {
        return fail("institution protected terms or policy labels rejected");
    }
    prompt_airlock::vault_client::ServiceOptions vault_options;
    vault_options.exe = paths->vault_executable;
    prompt_airlock::vault_client::VaultService vault(vault_options);

    // 감사 기록은 설정 파일 옆 audit/ 에 둔다(ADR 0021). 열지 못하면 기동하지 않는다.
    auto audit_log = prompt_airlock::audit::AuditLog::open(config_path.parent_path() / "audit",
                                                           std::chrono::days(config->history_retention_days));
    if (!audit_log) {
        return fail("cannot open the audit directory");
    }
    const std::string config_hash = core::sha256_hex(std::as_bytes(std::span(text->data(), text->size())));
    if (!(*audit_log)->append("start", "info", {{"config_sha256", config_hash}, {"origins", config->origins.size()}})) {
        return fail("cannot write the audit log");
    }
    asio::thread_pool work(gw::pipeline_work_threads);
    std::unique_ptr<prompt_airlock::provider::HttpsClient> https_provider;
    std::unique_ptr<prompt_airlock::provider::CliClient> cli_provider;
    gw::ProviderCall provider_call;
    if (config->provider.protocol == gw::ProviderProtocol::LocalCliText) {
        cli_provider = std::make_unique<prompt_airlock::provider::CliClient>(config->provider.cli, config->provider.model,
                                                                             work.get_executor());
        provider_call = [&cli_provider](std::string body, std::uint32_t output_token_limit) {
            return cli_provider->send(std::move(body), output_token_limit);
        };
    } else {
        https_provider = std::make_unique<prompt_airlock::provider::HttpsClient>(
            tls->client, prompt_airlock::provider::Endpoint{config->provider.host, config->provider.port,
                config->provider.target, config->provider.credential_mode, config->provider.api_version_header_name,
                config->provider.api_version_header_value}, config->provider.credential_file);
        provider_call = [&https_provider](std::string body, std::uint32_t) {
            return https_provider->send(std::move(body));
        };
    }
    gw::Pipeline pipeline(
        *detectors,
        [&vault]() -> std::expected<gw::PseudonymScope, core::VaultError> {
            auto scope = vault.open_scope();
            if (!scope) {
                return std::unexpected(core::VaultError::Unavailable);
            }
            return gw::PseudonymScope(std::move(*scope));
        },
        std::move(provider_call), config->output_token_cap,
        config->provider.model, work.get_executor(), audit_log->get(), gw::pipeline_in_flight_limit, gw::request_time_limit,
        std::move(*sentence), {}, config->provider.protocol);
    if (tls->cert_days && *tls->cert_days < 30) {
        std::fprintf(stderr, "prompt-airlock: warning: listen certificate expires in %d days\n", *tls->cert_days);
        (void)(*audit_log)->append("cert_expiry", "warn", {{"days_left", *tls->cert_days}});
    }
    gw::Authenticator auth(config->origins);

    asio::io_context io(static_cast<int>(io_threads));
    const asio::ip::tcp::endpoint endpoint(asio::ip::make_address(config->listen.address), config->listen.port);
    gw::Server server(io, tls->server, endpoint, auth,
                      [&pipeline](gw::AcceptedRequest request) { return pipeline.handle(std::move(request)); },
                      gw::ServerLimits{.body_bytes = gw::max_file_json_bytes}, audit_log->get(), config->compat.chat_app,
                      config->provider.credential_rotation_origin,
                      [credential_file = config->provider.credential_file](std::string_view credential) {
                          return prompt_airlock::provider::store_credential(credential_file, credential).has_value();
                      }, config->admin_history_origin);
    server.start();
    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](auto, auto) {
        server.stop();
        io.stop();
    });
    std::printf("prompt-airlock listening on https://%s:%u (origins %zu, protected terms %zu)\n",
                config->listen.address.c_str(), static_cast<unsigned>(server.local_endpoint().port()),
                config->origins.size(), config->internal_terms.size());
    std::fflush(stdout);
    std::vector<std::jthread> workers;
    for (unsigned i = 1; i < io_threads; ++i) {
        workers.emplace_back([&io] { io.run(); });
    }
    io.run();
    workers.clear();
    work.stop();  // 남은 작업은 버리고 돌고 있는 것만 끝낸다(pipeline 보다 먼저)
    work.join();
    (void)(*audit_log)->append("stop", "info", {});
    return 0;
}

// 256비트 무작위 값을 base64url(43자)로. random_device 는 운영체제 난수(Windows rand_s, Linux /dev/urandom)를 쓴다.
std::string random_token() {
    std::random_device device;
    std::array<unsigned char, 32> bytes{};
    for (std::size_t i = 0; i < bytes.size(); i += 4) {
        const unsigned value = device();
        for (std::size_t j = 0; j < 4; ++j) {
            bytes[i + j] = static_cast<unsigned char>(value >> (8 * j));
        }
    }
    constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    unsigned buffer = 0;
    int bits = 0;
    for (const unsigned char b : bytes) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(alphabet[(buffer >> bits) & 0x3f]);
        }
    }
    if (bits > 0) {
        out.push_back(alphabet[(buffer << (6 - bits)) & 0x3f]);
    }
    return out;
}

int issue_token(std::string_view origin) {
    const std::string token = random_token();
    const std::string hash = core::sha256_hex(std::as_bytes(std::span(token.data(), token.size())));
    std::printf("token (shown once, give it only to the origin app): %s\n", token.c_str());
    std::printf("config entry: {\"name\": \"%.*s\", \"token_sha256\": \"%s\", \"grade_policy\": \"o-only\"}\n",
                static_cast<int>(origin.size()), origin.data(), hash.c_str());
    return 0;
}

int keys_failure(gw::OriginFileError error) {
    const auto code = gw::origin_file_error_name(error);
    std::fprintf(stderr, "prompt-airlock: keys failed code=%.*s\n", static_cast<int>(code.size()), code.data());
    return 1;
}

std::string_view grade_policy_name(core::GradePolicy policy) {
    return policy == core::GradePolicy::OOnly ? "o-only" : "declare";
}

int keys_list(std::string_view config_path) {
    try {
        const std::filesystem::path config_file(config_path);
        const auto origins = gw::manage_origin_file(config_file, gw::OriginFileAction::List);
        if (!origins) return keys_failure(origins.error());
        for (const auto& origin : *origins) {
            const auto grade = grade_policy_name(origin.grade_policy);
            std::printf("%s %.*s\n", origin.name.c_str(), static_cast<int>(grade.size()), grade.data());
        }
        return 0;
    } catch (...) {
        return keys_failure(gw::OriginFileError::ReadFailed);
    }
}

int keys_add(std::string_view config_path, std::string_view name, std::string_view grade_text) {
    core::GradePolicy policy = core::GradePolicy::OOnly;
    if (!grade_text.empty()) {
        if (grade_text == "o-only") {
            policy = core::GradePolicy::OOnly;
        } else if (grade_text == "declare") {
            policy = core::GradePolicy::Declare;
        } else {
            return fail("keys failed code=invalid_grade");
        }
    }
    try {
        const std::filesystem::path config_file(config_path);
        core::SensitiveText token(random_token());
        const auto view = token.view();
        const std::string hash = core::sha256_hex(std::as_bytes(std::span(view.data(), view.size())));
        const auto added = gw::manage_origin_file(config_file, gw::OriginFileAction::Add, name, hash, policy);
        if (!added) return keys_failure(added.error());
        const int prefix_result = std::fputs("token: ", stdout);
        const std::size_t token_count = std::fwrite(view.data(), 1, view.size(), stdout);
        const int newline_result = std::fputc('\n', stdout);
        const int flush_result = std::fflush(stdout);
        if (prefix_result < 0 || token_count != view.size() || newline_result == EOF || flush_result != 0) {
            return fail("keys failed code=token_output_failed_registered; use keys revoke if token output was not captured");
        }
        return 0;
    } catch (...) {
        return keys_failure(gw::OriginFileError::WriteFailed);
    }
}

int keys_revoke(std::string_view config_path, std::string_view name) {
    try {
        const std::filesystem::path config_file(config_path);
        const auto revoked = gw::manage_origin_file(config_file, gw::OriginFileAction::Revoke, name);
        if (!revoked) return keys_failure(revoked.error());
        std::puts("keys: revoked");
        return 0;
    } catch (...) {
        return keys_failure(gw::OriginFileError::WriteFailed);
    }
}

struct SuggestFailure {
    std::string_view stage;
    std::string_view code;
    std::optional<std::size_t> file_index;
};

struct SuggestFile {
    std::filesystem::path path;
    std::string extension;
};

struct SuggestDirectoryAnchor {
#ifdef _WIN32
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~SuggestDirectoryAnchor() {
        if (handle != INVALID_HANDLE_VALUE) (void)CloseHandle(handle);
    }
#else
    int descriptor = -1;
    ~SuggestDirectoryAnchor() {
        if (descriptor >= 0) (void)::close(descriptor);
    }
#endif
};

struct SuggestFolder {
    std::unique_ptr<SuggestDirectoryAnchor> anchor;
    std::vector<SuggestFile> files;
    std::size_t directories_skipped = 0;
    std::size_t other_entries_skipped = 0;
    std::size_t bytes = 0;
};

struct SuggestCounters {
    std::size_t extracted = 0;
    std::size_t unsupported = 0;
    std::size_t no_text = 0;
    std::size_t duplicates = 0;
    std::size_t too_long = 0;
    std::size_t invalid_values = 0;
    std::size_t sensitive = 0;
};

struct SensitiveStringsWiper {
    std::vector<std::string>& values;
    ~SensitiveStringsWiper() {
        for (auto& value : values) {
            core::secure_wipe(std::span<char>(value.data(), value.size()));
        }
    }
};

int policy_suggest_failure(const SuggestFailure& failure) noexcept {
    if (failure.file_index) {
        std::fprintf(stderr, "policy-suggest: failed stage=%.*s code=%.*s file_index=%llu\n",
                     static_cast<int>(failure.stage.size()), failure.stage.data(),
                     static_cast<int>(failure.code.size()), failure.code.data(),
                     static_cast<unsigned long long>(*failure.file_index));
    } else {
        std::fprintf(stderr, "policy-suggest: failed stage=%.*s code=%.*s\n",
                     static_cast<int>(failure.stage.size()), failure.stage.data(),
                     static_cast<int>(failure.code.size()), failure.code.data());
    }
    return 1;
}

std::string extension_hint(const std::filesystem::path& path) {
    std::string extension = path.extension().string();
    if (!extension.empty() && extension.front() == '.') extension.erase(extension.begin());
    if (extension.size() > 10) return {};
    for (char& c : extension) {
        const auto byte = static_cast<unsigned char>(c);
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9'))) {
            return {};
        }
        if (byte >= 'A' && byte <= 'Z') c = static_cast<char>(byte + ('a' - 'A'));
    }
    return extension;
}

#ifdef _WIN32
std::optional<std::wstring> final_path_for_handle(HANDLE handle) {
    constexpr DWORD path_limit = 32768;
    const DWORD required = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (required == 0 || required > path_limit) return std::nullopt;
    std::wstring path(required, L'\0');
    const DWORD length = GetFinalPathNameByHandleW(handle, path.data(), required, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length == 0 || length >= required) return std::nullopt;
    path.resize(length);
    return path;
}

bool is_in_anchored_directory(HANDLE file, HANDLE directory) {
    const auto file_path = final_path_for_handle(file);
    const auto directory_path = final_path_for_handle(directory);
    if (!file_path || !directory_path) return false;
    const auto parent = std::filesystem::path(*file_path).parent_path().native();
    return CompareStringOrdinal(parent.data(), static_cast<int>(parent.size()), directory_path->data(),
                               static_cast<int>(directory_path->size()), TRUE) == CSTR_EQUAL;
}
#endif

std::expected<SuggestFolder, SuggestFailure> list_suggest_files(const std::filesystem::path& folder) {
    constexpr std::size_t max_entries = gw::max_file_parts;
    std::error_code ec;
    auto folder_entry = folder;
    while (folder_entry != folder_entry.root_path() &&
           (folder_entry.filename().empty() || folder_entry.filename() == ".")) {
        const auto parent = folder_entry.parent_path();
        if (parent.empty() || parent == folder_entry) break;
        folder_entry = parent;
    }
    auto anchor = std::make_unique<SuggestDirectoryAnchor>();
#ifdef _WIN32
    anchor->handle = CreateFileW(folder_entry.c_str(), FILE_READ_ATTRIBUTES,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (anchor->handle == INVALID_HANDLE_VALUE) {
        return std::unexpected(SuggestFailure{"folder", "unavailable", std::nullopt});
    }
    BY_HANDLE_FILE_INFORMATION folder_info{};
    if (!GetFileInformationByHandle(anchor->handle, &folder_info)) {
        return std::unexpected(SuggestFailure{"folder", "unavailable", std::nullopt});
    }
    if ((folder_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return std::unexpected(SuggestFailure{"folder", "path_boundary", std::nullopt});
    }
    if ((folder_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || GetFileType(anchor->handle) != FILE_TYPE_DISK) {
        return std::unexpected(SuggestFailure{"folder", "invalid_directory", std::nullopt});
    }
#else
    int folder_flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
#ifdef O_NOFOLLOW
    folder_flags |= O_NOFOLLOW;
#else
    return std::unexpected(SuggestFailure{"folder", "nofollow_unavailable", std::nullopt});
#endif
#ifdef O_DIRECTORY
    folder_flags |= O_DIRECTORY;
#else
    return std::unexpected(SuggestFailure{"folder", "directory_open_unavailable", std::nullopt});
#endif
    anchor->descriptor = ::open(folder_entry.c_str(), folder_flags);
    if (anchor->descriptor < 0) {
        if (errno == ELOOP) return std::unexpected(SuggestFailure{"folder", "path_boundary", std::nullopt});
        if (errno == ENOTDIR) return std::unexpected(SuggestFailure{"folder", "invalid_directory", std::nullopt});
        return std::unexpected(SuggestFailure{"folder", "unavailable", std::nullopt});
    }
    struct stat folder_info{};
    if (::fstat(anchor->descriptor, &folder_info) != 0) {
        return std::unexpected(SuggestFailure{"folder", "unavailable", std::nullopt});
    }
    if (!S_ISDIR(folder_info.st_mode)) {
        return std::unexpected(SuggestFailure{"folder", "invalid_directory", std::nullopt});
    }
#endif
    const auto root = std::filesystem::canonical(folder, ec);
    if (ec) return std::unexpected(SuggestFailure{"folder", "unavailable", std::nullopt});

    SuggestFolder result;
    result.anchor = std::move(anchor);
    auto current = std::filesystem::directory_iterator(root, ec);
    if (ec) return std::unexpected(SuggestFailure{"folder", "unavailable", std::nullopt});
    const std::filesystem::directory_iterator end;
    std::size_t entries = 0;
    while (current != end) {
        if (++entries > max_entries) {
            return std::unexpected(SuggestFailure{"limit", "entry_limit", std::nullopt});
        }
        const auto entry = current->path();
        const auto status = current->symlink_status(ec);
        if (ec) return std::unexpected(SuggestFailure{"folder", "entry_unavailable", std::nullopt});
        if (std::filesystem::is_symlink(status)) {
            return std::unexpected(SuggestFailure{"folder", "path_boundary", std::nullopt});
        }
#ifdef _WIN32
        const DWORD attributes = GetFileAttributesW(entry.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            return std::unexpected(SuggestFailure{"folder", "entry_unavailable", std::nullopt});
        }
        if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            return std::unexpected(SuggestFailure{"folder", "path_boundary", std::nullopt});
        }
#endif
        if (std::filesystem::is_directory(status)) {
            ++result.directories_skipped;
        } else if (!std::filesystem::is_regular_file(status)) {
            ++result.other_entries_skipped;
        } else {
            if (result.files.size() >= gw::max_file_parts) {
                return std::unexpected(SuggestFailure{"limit", "file_limit", std::nullopt});
            }
            const auto resolved = std::filesystem::canonical(entry, ec);
            if (ec || resolved.parent_path() != root) {
                return std::unexpected(SuggestFailure{"folder", "path_boundary", std::nullopt});
            }
            const auto size = std::filesystem::file_size(entry, ec);
            if (ec) return std::unexpected(SuggestFailure{"folder", "entry_unavailable", std::nullopt});
            if (size > gw::max_file_bytes || size > gw::max_file_bytes - result.bytes) {
                return std::unexpected(SuggestFailure{"limit", "input_limit", std::nullopt});
            }
            result.bytes += static_cast<std::size_t>(size);
            result.files.push_back({entry, extension_hint(entry)});
        }
        current.increment(ec);
        if (ec) return std::unexpected(SuggestFailure{"folder", "enumeration_failed", std::nullopt});
    }
    std::ranges::sort(result.files, {}, &SuggestFile::path);
    return result;
}

std::expected<core::SensitiveText, SuggestFailure> read_suggest_file(const SuggestFolder& folder,
                                                                     const SuggestFile& file,
                                                                     std::size_t limit,
                                                                     std::size_t index) {
#ifdef _WIN32
    HANDLE input = CreateFileW(file.path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                               FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (input == INVALID_HANDLE_VALUE) {
        return std::unexpected(SuggestFailure{"read", "unavailable", index});
    }
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    if (!GetFileInformationByHandle(input, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || GetFileType(input) != FILE_TYPE_DISK ||
        !is_in_anchored_directory(input, folder.anchor->handle) || !GetFileSizeEx(input, &size) || size.QuadPart < 0) {
        (void)CloseHandle(input);
        return std::unexpected(SuggestFailure{"read", "path_boundary", index});
    }
    if (static_cast<unsigned long long>(size.QuadPart) > limit) {
        (void)CloseHandle(input);
        return std::unexpected(SuggestFailure{"limit", "input_limit", index});
    }
    std::string bytes(static_cast<std::size_t>(size.QuadPart), '\0');
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto remaining = bytes.size() - offset;
        const DWORD chunk = remaining > std::numeric_limits<DWORD>::max()
            ? std::numeric_limits<DWORD>::max() : static_cast<DWORD>(remaining);
        DWORD count = 0;
        if (!ReadFile(input, bytes.data() + offset, chunk, &count, nullptr) || count == 0) {
            (void)CloseHandle(input);
            return std::unexpected(SuggestFailure{"read", "read_failed", index});
        }
        offset += count;
    }
    if (!CloseHandle(input)) return std::unexpected(SuggestFailure{"read", "read_failed", index});
    return core::SensitiveText(std::move(bytes));
#else
    int flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#else
    return std::unexpected(SuggestFailure{"read", "nofollow_unavailable", index});
#endif
    const auto filename = file.path.filename();
    if (filename.empty() || filename == "." || filename == "..") {
        return std::unexpected(SuggestFailure{"read", "path_boundary", index});
    }
    const int input = ::openat(folder.anchor->descriptor, filename.c_str(), flags);
    if (input < 0) {
        return std::unexpected(SuggestFailure{"read", errno == ELOOP ? "path_boundary" : "unavailable", index});
    }
    struct stat before{};
    if (::fstat(input, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size < 0) {
        (void)::close(input);
        return std::unexpected(SuggestFailure{"read", "path_boundary", index});
    }
    if (static_cast<std::uintmax_t>(before.st_size) > limit) {
        (void)::close(input);
        return std::unexpected(SuggestFailure{"limit", "input_limit", index});
    }
    std::string bytes(static_cast<std::size_t>(before.st_size), '\0');
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = ::read(input, bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            (void)::close(input);
            return std::unexpected(SuggestFailure{"read", "read_failed", index});
        }
        offset += static_cast<std::size_t>(count);
    }
    char extra = 0;
    const auto extra_count = ::read(input, &extra, 1);
    struct stat after{};
    const bool stable = extra_count == 0 && ::fstat(input, &after) == 0 && before.st_dev == after.st_dev &&
                        before.st_ino == after.st_ino && before.st_size == after.st_size &&
                        before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
                        before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
    (void)::close(input);
    if (!stable) return std::unexpected(SuggestFailure{"read", "file_changed", index});
    return core::SensitiveText(std::move(bytes));
#endif
}

std::optional<std::string_view> labeled_policy_value(std::string_view line) noexcept {
    const auto trim = [](std::string_view value) {
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r')) {
            value.remove_prefix(1);
        }
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
            value.remove_suffix(1);
        }
        return value;
    };
    line = trim(line);
    static constexpr std::array<std::string_view, 4> labels = {"연구과제명", "프로젝트명", "사업명", "과제명"};
    for (const auto label : labels) {
        if (!line.starts_with(label)) continue;
        auto value = line.substr(label.size());
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
        if (value.empty() || (value.front() != ':' && value.front() != '=' && !value.starts_with("："))) {
            return std::nullopt;
        }
        value.remove_prefix(value.starts_with("：") ? std::string_view("：").size() : 1);
        value = trim(value);
        static constexpr std::array<std::pair<std::string_view, std::string_view>, 5> quotes = {{{"\"", "\""},
            {"'", "'"}, {"“", "”"}, {"‘", "’"}, {"「", "」"}}};
        for (const auto& [open, close] : quotes) {
            if (value.starts_with(open) && value.ends_with(close) && value.size() >= open.size() + close.size()) {
                value.remove_prefix(open.size());
                value.remove_suffix(close.size());
                value = trim(value);
                break;
            }
        }
        return value.empty() ? std::nullopt : std::optional(value);
    }
    return std::nullopt;
}

enum class CandidateCheck { Valid, InvalidUtf8, TooLong, Control, Invisible };

CandidateCheck check_policy_candidate(std::string_view value) {
    if (!core::validate_utf8(value)) return CandidateCheck::InvalidUtf8;
    if (value.empty() || value.size() > detect::max_id_label_length * 4) return CandidateCheck::TooLong;
    const auto decoded = core::decode_utf8(value);
    if (!decoded) return CandidateCheck::InvalidUtf8;
    if (decoded->empty() || decoded->size() > detect::max_id_label_length) return CandidateCheck::TooLong;
    for (const auto& point : *decoded) {
        if (point.value < 0x20 || (point.value >= 0x7F && point.value < 0xA0) || point.value == 0x2028 ||
            point.value == 0x2029 || point.value == 0xFFFE || point.value == 0xFFFF) {
            return CandidateCheck::Control;
        }
    }
    const auto view = detect::make_view(value);
    if (!view || view->units.empty()) return CandidateCheck::Invisible;
    std::size_t covered = 0;
    for (const auto& unit : view->units) {
        const auto begin = unit.source.begin().value();
        const auto end = unit.source.end().value();
        if (begin > covered) return CandidateCheck::Invisible;
        covered = std::max(covered, end);
    }
    return covered == value.size() ? CandidateCheck::Valid : CandidateCheck::Invisible;
}

void wipe_strings(std::vector<std::string>& values) noexcept {
    for (auto& value : values) core::secure_wipe(std::span<char>(value.data(), value.size()));
}

std::optional<SuggestFailure> collect_policy_candidates(gw::ResolvedDocuments& documents,
                                                        std::vector<std::string>& candidates,
                                                        SuggestCounters& counters,
                                                        std::size_t& candidate_bytes) {
    constexpr std::size_t max_candidates = detect::max_confidential_terms;
    constexpr std::size_t max_candidate_bytes = detect::max_confidential_terms * detect::max_id_label_length * 4;
    for (const auto& segment : documents.document.segments()) {
        const auto text = segment.text();
        std::size_t start = 0;
        while (start <= text.size()) {
            const auto end = text.find('\n', start);
            auto line = text.substr(start, end == std::string_view::npos ? text.size() - start : end - start);
            if (const auto value = labeled_policy_value(line)) {
                switch (check_policy_candidate(*value)) {
                    case CandidateCheck::InvalidUtf8:
                    case CandidateCheck::Control:
                    case CandidateCheck::Invisible:
                        ++counters.invalid_values;
                        break;
                    case CandidateCheck::TooLong:
                        ++counters.too_long;
                        break;
                    case CandidateCheck::Valid:
                        if (std::ranges::find(candidates, *value) != candidates.end()) {
                            ++counters.duplicates;
                        } else {
                            if (candidates.size() >= max_candidates || value->size() > max_candidate_bytes - candidate_bytes) {
                                return SuggestFailure{"limit", "candidate_limit", std::nullopt};
                            }
                            candidates.emplace_back(*value);
                            candidate_bytes += value->size();
                        }
                        break;
                }
            }
            if (end == std::string_view::npos) break;
            start = end + 1;
        }
    }
    return std::nullopt;
}

int policy_suggest(std::string_view folder_arg) noexcept {
    constexpr std::size_t total_input_limit = gw::max_file_bytes;
    try {
        const auto folder = std::filesystem::path(folder_arg);
        auto inventory = list_suggest_files(folder);
        if (!inventory) return policy_suggest_failure(inventory.error());
        if (inventory->files.empty()) {
            std::printf("policy-suggest: state=empty files=0 directories_skipped=%llu\n",
                        static_cast<unsigned long long>(inventory->directories_skipped));
            return 0;
        }

        std::vector<std::string> candidates;
        SensitiveStringsWiper candidates_wiper{candidates};
        SuggestCounters counters;
        std::size_t input_bytes = 0;
        std::size_t extracted_bytes = 0;
        std::size_t candidate_bytes = 0;
        for (std::size_t index = 0; index < inventory->files.size(); ++index) {
            const auto& file = inventory->files[index];
            const auto remaining = total_input_limit - input_bytes;
            auto bytes = read_suggest_file(*inventory, file, remaining, index + 1);
            if (!bytes) return policy_suggest_failure(bytes.error());
            input_bytes += bytes->size();

            core::PromptDocumentBuilder builder;
            std::vector<core::SensitiveText> placeholder;
            placeholder.emplace_back(std::string("policy-suggest-placeholder"));
            builder.add_message(core::MessageRole::User, core::ContentForm::TextParts, std::move(placeholder));
            auto prompt = std::move(builder).build();
            if (!prompt) return policy_suggest_failure({"request", "invalid_placeholder", index + 1});
            std::vector<gw::FilePart> files;
            files.push_back({0, 0, file.extension, std::move(*bytes)});
            gw::ParsedRequest request{std::move(*prompt), {}, std::move(files)};
            std::vector<gw::FileStatistics> statistics;
            auto resolved = gw::resolve_documents(request, extract::default_executable(), statistics, {});
            if (!resolved) {
                if (const auto* extraction = std::get_if<extract::ExtractError>(&resolved.error())) {
                    if (*extraction == extract::ExtractError::Unsupported || *extraction == extract::ExtractError::LegacyFormat ||
                        *extraction == extract::ExtractError::UnknownFormat) {
                        ++counters.unsupported;
                        continue;
                    }
                    if (*extraction == extract::ExtractError::NoText) {
                        ++counters.no_text;
                        continue;
                    }
                    const auto code = extract::error_name(*extraction);
                    return policy_suggest_failure({"extract", code, index + 1});
                }
                if (const auto* runner = std::get_if<extract::RunError>(&resolved.error())) {
                    const auto code = extract::run_error_name(*runner);
                    return policy_suggest_failure({"runner", code, index + 1});
                }
                return policy_suggest_failure({"extract", "invalid_text", index + 1});
            }
            const auto text_bytes = resolved->document.total_bytes();
            if (text_bytes > core::max_document_text_bytes - extracted_bytes) {
                return policy_suggest_failure({"limit", "text_limit", index + 1});
            }
            extracted_bytes += text_bytes;
            ++counters.extracted;
            if (auto error = collect_policy_candidates(*resolved, candidates, counters, candidate_bytes)) {
                return policy_suggest_failure(*error);
            }
        }

        if (!candidates.empty()) {
            detect::InstitutionPolicy candidate_policy;
            candidate_policy.confidential_subjects = candidates;
            {
                const std::span<const std::string_view> no_terms;
                const auto validated = detect::Detectors::make(no_terms, {}, candidate_policy);
                wipe_strings(candidate_policy.confidential_subjects);
                if (!validated) return policy_suggest_failure({"policy", "invalid_candidate", std::nullopt});
            }

            const auto paths = runtime_paths();
            if (!paths) return policy_suggest_failure({"runtime", paths.error(), std::nullopt});
            auto ner = prompt_airlock::ner::NerPool::make(paths->ner_model_dir);
            if (!ner) return policy_suggest_failure({"detector", "unavailable", std::nullopt});
            const std::span<const std::string_view> no_terms;
            const auto detectors = detect::Detectors::make(no_terms, *ner);
            if (!detectors) return policy_suggest_failure({"detector", "unavailable", std::nullopt});
            std::vector<std::string> safe_candidates;
            SensitiveStringsWiper safe_candidates_wiper{safe_candidates};
            for (auto& candidate : candidates) {
                const auto entities = detectors->detect_segment(candidate, core::SegmentIndex{0});
                if (!entities) return policy_suggest_failure({"detector", "scan_failed", std::nullopt});
                const bool sensitive = std::ranges::any_of(*entities, [](const core::EntitySpan& entity) {
                    return entity.type() != core::EntityType::Organization;
                });
                if (sensitive) {
                    ++counters.sensitive;
                    core::secure_wipe(std::span<char>(candidate.data(), candidate.size()));
                } else {
                    safe_candidates.push_back(std::move(candidate));
                }
            }
            candidates = std::move(safe_candidates);
            safe_candidates_wiper.values.clear();
        }

        std::ranges::sort(candidates);
        const bool partial = counters.unsupported != 0 || counters.no_text != 0 || inventory->other_entries_skipped != 0;
        const std::string_view state = inventory->files.empty() ? "empty"
                                    : counters.extracted == 0 ? "no_supported_documents"
                                    : partial ? "partial_unsupported"
                                              : "complete";
        std::printf("policy-suggest: state=%.*s files=%llu extracted=%llu unsupported=%llu no_text=%llu "
                    "directories_skipped=%llu other_entries_skipped=%llu duplicates=%llu too_long=%llu "
                     "invalid_rejected=%llu sensitive_rejected=%llu candidates=%llu review_required=true applied=false\n",
                    static_cast<int>(state.size()), state.data(),
                    static_cast<unsigned long long>(inventory->files.size()),
                    static_cast<unsigned long long>(counters.extracted),
                    static_cast<unsigned long long>(counters.unsupported),
                    static_cast<unsigned long long>(counters.no_text),
                    static_cast<unsigned long long>(inventory->directories_skipped),
                    static_cast<unsigned long long>(inventory->other_entries_skipped),
                    static_cast<unsigned long long>(counters.duplicates),
                    static_cast<unsigned long long>(counters.too_long),
                     static_cast<unsigned long long>(counters.invalid_values),
                    static_cast<unsigned long long>(counters.sensitive),
                    static_cast<unsigned long long>(candidates.size()));
        for (const auto& candidate : candidates) {
            std::fputs("candidate: ", stdout);
            (void)std::fwrite(candidate.data(), 1, candidate.size(), stdout);
            std::fputc('\n', stdout);
        }
        if (std::fflush(stdout) != 0) return fail("policy-suggest: output_failed");
        return 0;
    } catch (...) {
        return fail("policy-suggest: failed stage=internal code=operation_failed");
    }
}

int protect_credential_file(std::string_view in, const std::filesystem::path& out) {
    // 갱신 작업이 평문을 디스크에 남기지 않도록 - 면 표준 입력에서 읽는다.
    auto plain = in == "-" ? std::optional<std::string>(std::string(std::istreambuf_iterator<char>(std::cin), {}))
                           : read_file(std::filesystem::path(in));
    if (!plain) {
        return fail("cannot read the plain credential file");
    }
    const prompt_airlock::core::SensitiveText owned(std::move(*plain));
    if (auto stored = prompt_airlock::provider::store_credential(out, owned.view()); !stored) {
        return fail(stored.error() == prompt_airlock::provider::CredentialError::NotProtected
                        ? "cannot protect the credential"
                        : "cannot replace the protected credential file (try again)");
    }
    if (in != "-") {
        std::printf("protected credential written to %s; delete the plain file\n", out.string().c_str());
    }
    return 0;
}

// 감사 기록 로컬 열람·검증. 서버와 같은 줄에 쓰지 않도록 관리 기록은 admin/ 아래 따로 이어 붙인다.
int audit_command(std::string_view action, const std::filesystem::path& dir, int lines) {
    namespace audit = prompt_airlock::audit;
    auto admin = audit::AuditLog::open(dir / "admin", audit::minimum_retention);
    if (!admin) {
        return fail("cannot open the admin log");
    }
    if (action == "verify") {
        const auto main_log = audit::verify(dir);
        const auto admin_log = audit::verify(dir / "admin");
        (void)(*admin)->append("audit_verify", "info", {{"ok", main_log.has_value() && admin_log.has_value()}});
        if (!main_log) {
            std::printf("audit: FAILED (%s)\n", std::string(audit::audit_error_name(main_log.error())).c_str());
            return 1;
        }
        std::printf("audit: ok, %d segments, %llu lines\n", main_log->segments,
                    static_cast<unsigned long long>(main_log->lines));
        return admin_log ? 0 : 1;
    }
    if (action == "list") {
        std::vector<std::filesystem::path> files;
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (entry.path().extension() == ".jsonl") {
                files.push_back(entry.path());
            }
        }
        std::ranges::sort(files);
        if (files.empty()) {
            return fail("no audit segments");
        }
        std::ifstream in(files.back(), std::ios::binary);
        std::vector<std::string> all;
        for (std::string line; std::getline(in, line);) {
            all.push_back(line);
        }
        const auto first = all.size() > static_cast<std::size_t>(lines) ? all.size() - static_cast<std::size_t>(lines) : 0;
        for (auto i = first; i < all.size(); ++i) {
            std::printf("%s\n", all[i].c_str());
        }
        (void)(*admin)->append("audit_view", "info",
                               {{"segment", files.back().filename().string()}, {"lines", all.size() - first}});
        return 0;
    }
    return fail("unknown audit action");
}

}  // namespace

int main(int argc, char** argv) try {
    const std::string_view command = argc > 1 ? argv[1] : "";
    if (command == "serve" && argc == 3) {
        return serve(argv[2]);
    }
    if (command == "check" && argc == 3) {
        return check_command(argv[2]);
    }
    if (command == "check" && argc == 4 && std::string_view(argv[3]) == "--connect") {
        return check_command(argv[2], true);
    }
    if (command == "stats" && argc == 3) {
        return stats_command(argv[2]);
    }
    if (command == "issue-token" && argc == 3) {
        return issue_token(argv[2]);
    }
    if (command == "keys" && argc == 4 && std::string_view(argv[2]) == "list") {
        return keys_list(argv[3]);
    }
    if (command == "keys" && argc == 5 && std::string_view(argv[2]) == "revoke") {
        return keys_revoke(argv[3], argv[4]);
    }
    if (command == "keys" && (argc == 5 || argc == 6) && std::string_view(argv[2]) == "add") {
        return keys_add(argv[3], argv[4], argc == 6 ? std::string_view(argv[5]) : std::string_view{});
    }
    if (command == "policy" && argc == 4 && std::string_view(argv[2]) == "suggest") {
        return policy_suggest(argv[3]);
    }
    if (command == "protect-credential" && argc == 4) {
        return protect_credential_file(argv[2], argv[3]);
    }
    if (command == "audit" && (argc == 4 || argc == 5)) {
        return audit_command(argv[2], argv[3], argc == 5 ? std::atoi(argv[4]) : 20);
    }
    std::fputs("usage: prompt-airlock serve <config.json>\n       prompt-airlock check <config.json> [--connect]\n"
               "       prompt-airlock stats <audit-dir>\n"
               "       prompt-airlock issue-token <origin-name>\n"
               "       prompt-airlock keys list <config.json>\n"
               "       prompt-airlock keys add <config.json> <origin-name> [o-only|declare]\n"
               "       prompt-airlock keys revoke <config.json> <origin-name>\n"
               "       prompt-airlock policy suggest <institution-document-dir>\n"
               "       prompt-airlock protect-credential <plain-file|-> <out-file>\n"
               "       prompt-airlock audit verify|list <audit-dir> [lines]\n",
               stderr);
    return 2;
} catch (const std::exception& e) {
    std::fprintf(stderr, "prompt-airlock: %s\n", e.what());
    return 1;
}
