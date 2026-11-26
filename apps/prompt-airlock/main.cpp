// 게이트웨이 실행 파일.
//   prompt-airlock serve <config.json>      설정 하나로 Vault, NER pool, HTTPS 서버를 띄운다
//   prompt-airlock issue-token <origin>      출처 token 을 발급한다(원문은 이때 한 번만 출력, 설정에는 해시만)
//   prompt-airlock keys add|list|revoke <config.json> ...  설정 파일의 출처 키를 관리한다
//   prompt-airlock protect-credential <평문 파일|-> <출력 파일>   provider 자격 증명을 보호 저장한다(Windows DPAPI, Linux 0600).
//                                       - 는 표준 입력. 실행 중인 게이트웨이는 다음 요청부터 새 값을 쓴다(ADR 0026)
//   prompt-airlock audit verify|list <감사 폴더> [줄 수]       감사 기록을 로컬에서 검증·열람한다(관리 기록은 admin/ 에)
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/signal_set.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstdio>
#include <exception>
#include <expected>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include "prompt_airlock/audit/log.hpp"
#include "prompt_airlock/core/sha256.hpp"
#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/gateway/auth.hpp"
#include "prompt_airlock/gateway/config.hpp"
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
namespace gw = prompt_airlock::gateway;

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
std::expected<gw::SentenceCheck, const char*> make_sentence_check(bool enabled) {
    if (!enabled) {
        return gw::SentenceCheck{};
    }
    auto classifier = prompt_airlock::ner::SentenceClassifier::make(PA_SENTENCE_MODEL_DIR);
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

// 요청·감사·제공자 실행 없이 현재 설정의 로컬 준비 상태만 확인한다.
int check_command(std::string_view config_arg) noexcept {
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

        const auto tls = load_tls(*config);
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

        auto ner = prompt_airlock::ner::NerPool::make(PA_NER_MODEL_DIR);
        if (!ner) {
            return check_failure("model", "ner_unavailable");
        }
        auto sentence = make_sentence_check(config->sentence_warn);
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
            vault_options.exe = PA_VAULT_EXE;
            prompt_airlock::vault_client::VaultService vault(vault_options);
            {
                auto scope = vault.open_scope();
                if (!scope) {
                    return check_failure("vault", "unavailable");
                }
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
        } else {
            std::puts("provider_connection: not_tested");
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

    // shortcut: 모델 폴더와 Vault 실행 파일은 빌드 트리 경로를 쓴다. 배포 묶음(Phase 13)에서 실행 파일 옆으로 옮긴다.
    auto ner = prompt_airlock::ner::NerPool::make(PA_NER_MODEL_DIR);
    if (!ner) {
        return fail("NER model files are missing or do not match the pinned hashes");
    }
    auto sentence = make_sentence_check(config->sentence_warn);
    if (!sentence) {
        return fail(sentence.error());
    }
    std::vector<std::string_view> terms(config->internal_terms.begin(), config->internal_terms.end());
    auto detectors = prompt_airlock::detect::Detectors::make(terms, *ner, config->policy);
    if (!detectors) {
        return fail("institution protected terms or policy labels rejected");
    }
    prompt_airlock::vault_client::ServiceOptions vault_options;
    vault_options.exe = PA_VAULT_EXE;
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
    if (command == "protect-credential" && argc == 4) {
        return protect_credential_file(argv[2], argv[3]);
    }
    if (command == "audit" && (argc == 4 || argc == 5)) {
        return audit_command(argv[2], argv[3], argc == 5 ? std::atoi(argv[4]) : 20);
    }
    std::fputs("usage: prompt-airlock serve <config.json>\n       prompt-airlock check <config.json>\n"
               "       prompt-airlock stats <audit-dir>\n"
               "       prompt-airlock issue-token <origin-name>\n"
               "       prompt-airlock keys list <config.json>\n"
               "       prompt-airlock keys add <config.json> <origin-name> [o-only|declare]\n"
               "       prompt-airlock keys revoke <config.json> <origin-name>\n"
               "       prompt-airlock protect-credential <plain-file|-> <out-file>\n"
               "       prompt-airlock audit verify|list <audit-dir> [lines]\n",
               stderr);
    return 2;
} catch (const std::exception& e) {
    std::fprintf(stderr, "prompt-airlock: %s\n", e.what());
    return 1;
}
