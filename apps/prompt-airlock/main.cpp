// 게이트웨이 실행 파일.
//   prompt-airlock serve <config.json>      설정 하나로 Vault, NER pool, HTTPS 서버를 띄운다
//   prompt-airlock issue-token <origin>      출처 token 을 발급한다(원문은 이때 한 번만 출력, 설정에는 해시만)
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

#include <array>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iterator>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "prompt_airlock/core/sha256.hpp"
#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/gateway/auth.hpp"
#include "prompt_airlock/gateway/config.hpp"
#include "prompt_airlock/gateway/pipeline.hpp"
#include "prompt_airlock/gateway/server.hpp"
#include "prompt_airlock/ner/pool.hpp"
#include "prompt_airlock/provider/https_client.hpp"
#include "prompt_airlock/tls/context.hpp"
#include "prompt_airlock/vault_client/service.hpp"

namespace {

namespace asio = boost::asio;
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
    const auto cert = read_file(config->listen.certificate_chain);
    const auto key = read_file(config->listen.private_key);
    if (!cert || !key) {
        return fail("cannot read the listen certificate or key");
    }
    auto server_tls = prompt_airlock::tls::make_server_context(*cert, *key);
    if (!server_tls) {
        return fail("listen certificate or key rejected (weak key, bad PEM or mismatched pair)");
    }
    std::optional<std::string> trust;
    if (!config->provider.trust_file.empty() && !(trust = read_file(config->provider.trust_file))) {
        return fail("cannot read the provider trust file");
    }
    auto client_tls = prompt_airlock::tls::make_client_context(trust ? std::optional<std::string_view>(*trust)
                                                                     : std::nullopt);
    if (!client_tls) {
        return fail("provider trust store rejected");
    }
    auto credential = prompt_airlock::provider::load_credential(config->provider.credential_file);
    if (!credential) {
        return fail("provider credential file is missing, empty or has invalid characters");
    }

    // shortcut: 모델 폴더와 Vault 실행 파일은 빌드 트리 경로를 쓴다. 배포 묶음(Phase 13)에서 실행 파일 옆으로 옮긴다.
    auto ner = prompt_airlock::ner::NerPool::make(PA_NER_MODEL_DIR);
    if (!ner) {
        return fail("NER model files are missing or do not match the pinned hashes");
    }
    std::vector<std::string_view> terms(config->internal_terms.begin(), config->internal_terms.end());
    auto detectors = prompt_airlock::detect::Detectors::make(terms, *ner);
    if (!detectors) {
        return fail("institution protected terms rejected");
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
    prompt_airlock::provider::HttpsClient provider(
        *client_tls, {config->provider.host, config->provider.port, config->provider.target}, std::move(*credential));
    gw::Pipeline pipeline(
        *detectors,
        [&vault]() -> std::expected<gw::PseudonymScope, core::VaultError> {
            auto scope = vault.open_scope();
            if (!scope) {
                return std::unexpected(core::VaultError::Unavailable);
            }
            return gw::PseudonymScope(std::move(*scope));
        },
        [&provider](std::string body) { return provider.send(std::move(body)); }, config->output_token_cap,
        config->provider.model, audit_log->get());
    gw::Authenticator auth(config->origins);

    asio::io_context io(static_cast<int>(io_threads));
    const asio::ip::tcp::endpoint endpoint(asio::ip::make_address(config->listen.address), config->listen.port);
    gw::Server server(io, *server_tls, endpoint, auth,
                      [&pipeline](gw::AcceptedRequest request) { return pipeline.handle(std::move(request)); },
                      gw::ServerLimits{}, audit_log->get());
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

}  // namespace

int main(int argc, char** argv) try {
    const std::string_view command = argc > 1 ? argv[1] : "";
    if (command == "serve" && argc == 3) {
        return serve(argv[2]);
    }
    if (command == "issue-token" && argc == 3) {
        return issue_token(argv[2]);
    }
    std::fputs("usage: prompt-airlock serve <config.json>\n       prompt-airlock issue-token <origin-name>\n", stderr);
    return 2;
} catch (const std::exception& e) {
    std::fprintf(stderr, "prompt-airlock: %s\n", e.what());
    return 1;
}
