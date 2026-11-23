#include "prompt_airlock/gateway/server.hpp"

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/none.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <algorithm>
#include <array>

#include "prompt_airlock/core/types.hpp"
#include "prompt_airlock/core/sensitive.hpp"
#include <exception>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "prompt_airlock/gateway/confirm.hpp"
#include "prompt_airlock/gateway/response_json.hpp"
#include "console_assets.hpp"

namespace prompt_airlock::gateway {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;

namespace {
// Windows 의 SO_REUSEADDR 은 이미 쓰는 포트를 다른 소켓이 가로채게 허용하므로 끈다. 다른 플랫폼은 재시작 때 TIME_WAIT 를 넘기려고 켠다.
#ifdef _WIN32
constexpr bool reuse_address = false;
#else
constexpr bool reuse_address = true;
#endif
}  // namespace

struct Server::Shared {
    Shared(asio::io_context& io, asio::ssl::context& tls_context, const tcp::endpoint& endpoint, Authenticator& authenticator,
           RequestHandler request_handler, ServerLimits server_limits, audit::AuditLog* audit_log, bool chat_compat,
           std::string rotation_origin, CredentialRotationWriter credential_writer)
        : tls(tls_context),
          acceptor(io, endpoint, reuse_address),
          port(acceptor.local_endpoint().port()),
          auth(authenticator),
          handler(std::move(request_handler)),
          limits(server_limits),
          audit(audit_log), chat_app_compat(chat_compat), credential_rotation_origin(std::move(rotation_origin)),
          credential_rotation_writer(std::move(credential_writer)) {}

    asio::ssl::context& tls;
    tcp::acceptor acceptor;
    const std::uint16_t port;
    Authenticator& auth;
    RequestHandler handler;
    ServerLimits limits;
    audit::AuditLog* audit;
    const bool chat_app_compat;
    const std::string credential_rotation_origin;
    const CredentialRotationWriter credential_rotation_writer;
    std::atomic<std::size_t> connections{0};
    std::atomic<std::size_t> large_preparations{0};
};

struct UploadLease {
    explicit UploadLease(std::shared_ptr<Server::Shared> owner) : state(std::move(owner)) {}
    UploadLease(const UploadLease&) = delete;
    UploadLease& operator=(const UploadLease&) = delete;
    ~UploadLease() { if (acquired) state->large_preparations.fetch_sub(1); }
    std::shared_ptr<Server::Shared> state;
    bool acquired = false;
};

std::shared_ptr<UploadLease> reserve_large_upload(const std::shared_ptr<Server::Shared>& state) {
    auto lease = std::make_shared<UploadLease>(state);
    auto count = state->large_preparations.load();
    while (count < 2) {
        if (state->large_preparations.compare_exchange_weak(count, count + 1)) {
            lease->acquired = true;
            return lease;
        }
    }
    return {};
}

namespace {

using Stream = beast::ssl_stream<beast::tcp_stream>;
using Parser = http::request_parser<http::buffer_body>;
struct BodyCleanup {
    std::string& body;
    ~BodyCleanup() { core::SensitiveText discarded(std::move(body)); }
};
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

constexpr std::string_view endpoint_path = "/v1/chat/completions";
constexpr std::string_view preview_path = "/v1/preview";
constexpr std::string_view approval_path = "/v1/confirmations/approve";
constexpr std::string_view credential_rotation_path = "/v1/provider/credential";
constexpr std::string_view grade_header = "X-Prompt-Airlock-Grade";  // ADR 0013
constexpr std::string_view confirm_header = "X-Prompt-Airlock-Confirm";  // ADR 0023

std::string console_origin(std::uint16_t port) {
    return "https://127.0.0.1" + (port == 443 ? std::string{} : ":" + std::to_string(port));
}

bool local_console_request(const http::request_header<>& head, std::string_view client, std::uint16_t port) {
    const auto origin = console_origin(port);
    return client == "127.0.0.1" && head.count(http::field::host) == 1 &&
           head[http::field::host] == std::string_view(origin).substr(8) &&
           head.count(http::field::origin) <= 1 &&
           (head.count(http::field::origin) == 0 || head[http::field::origin] == std::string_view(origin));
}

std::optional<JsonResponse> console_resource(const http::request_header<>& head, std::string_view client,
                                             std::uint16_t port) {
    const std::string_view target = head.target();
    const bool page = target == "/console/confirm" || target.starts_with("/console/confirm?");
    if (!page && target != "/console/confirm.js" && target != "/console/confirm.css" &&
        target != "/console/confirm.svg") return std::nullopt;
    if (!local_console_request(head, client, port)) return error_response(EntryError::LocalOnly);
    if (head.method() != http::verb::get) return error_response(EntryError::MethodNotAllowed);
    if (page) {
        constexpr std::string_view prefix = "/console/confirm?token=";
        if (target != "/console/confirm" &&
            (!target.starts_with(prefix) || !valid_confirmation_token(target.substr(prefix.size())))) {
            return error_response(EntryError::BadRequest);
        }
        return JsonResponse{200, std::string(console_assets::confirmation_html), ResponseMedia::Html};
    }
    if (target == "/console/confirm.js") {
        return JsonResponse{200, std::string(console_assets::confirmation_js), ResponseMedia::JavaScript};
    }
    if (target == "/console/confirm.svg") {
        return JsonResponse{200, std::string(console_assets::confirmation_svg), ResponseMedia::Svg};
    }
    return JsonResponse{200, std::string(console_assets::confirmation_css), ResponseMedia::Css};
}

JsonResponse chat_notice(JsonResponse reply, std::uint16_t port) {
    if (reply.media != ResponseMedia::Json) return reply;
    const auto body = nlohmann::json::parse(reply.body, nullptr, false);
    if (!body.is_object() || !body.contains("error") || !body["error"].is_object()) return reply;
    const auto& error = body["error"];
    if (!error.contains("code") || !error["code"].is_string()) return reply;
    const auto code = error["code"].get<std::string>();
    std::string content;
    nlohmann::json protection = {{"reason", code}};
    if (reply.status == 409 && code == "confirmation_required") {
        if (!error.contains("confirm_token") || !error["confirm_token"].is_string()) return reply;
        const auto& token = error["confirm_token"].get_ref<const std::string&>();
        if (!valid_confirmation_token(token)) return reply;
        const auto url = console_origin(port) + "/console/confirm?token=" + token;
        content = "확인이 필요해 아직 외부로 보내지 않았습니다. [로컬 콘솔에서 확인](" + url +
                  ")한 뒤 원래 앱에서 같은 요청을 다시 생성하세요.";
        protection["decision"] = "confirmation_required";
        protection["approval_url"] = url;
    } else if ((reply.status == 400 && code == "entity_blocked") ||
               (reply.status == 403 && (code == "grade_classified" || code == "grade_sensitive" || code == "grade_unresolved"))) {
        content = "보호 정책에 따라 요청이 차단됐습니다. 외부로 보내지 않았으며, 확인 승인으로 전송할 수 없습니다.";
        protection["decision"] = "blocked";
        if (error.contains("blocked_types")) protection["blocked_types"] = error["blocked_types"];
    } else {
        return reply;
    }
    const auto created = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto response = nlohmann::json::parse(client_response_body(new_request_id(), created, "prompt-airlock", content,
                                                              "stop", std::nullopt));
    response["prompt_airlock"] = std::move(protection);
    return {200, response.dump()};
}

bool ascii_iequal_prefix(std::string_view text, std::string_view prefix) {
    if (text.size() < prefix.size()) {
        return false;
    }
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        const char c = text[i] >= 'A' && text[i] <= 'Z' ? static_cast<char>(text[i] - 'A' + 'a') : text[i];
        if (c != prefix[i]) {
            return false;
        }
    }
    return true;
}

// application/json, 뒤에 ";charset=..." 같은 매개변수는 허용한다.
bool is_json(std::string_view content_type) {
    constexpr std::string_view type = "application/json";
    if (!ascii_iequal_prefix(content_type, type)) {
        return false;
    }
    const std::string_view rest = content_type.substr(type.size());
    return rest.empty() || rest.front() == ';' || rest.front() == ' ';
}

http::response<http::string_body> make_reply(JsonResponse reply, unsigned version, bool keep_alive) {
    http::response<http::string_body> res{static_cast<http::status>(reply.status), version};
    switch (reply.media) {
        case ResponseMedia::Json: res.set(http::field::content_type, "application/json"); break;
        case ResponseMedia::Html: res.set(http::field::content_type, "text/html; charset=utf-8"); break;
        case ResponseMedia::JavaScript: res.set(http::field::content_type, "text/javascript; charset=utf-8"); break;
        case ResponseMedia::Css: res.set(http::field::content_type, "text/css; charset=utf-8"); break;
        case ResponseMedia::Svg: res.set(http::field::content_type, "image/svg+xml"); break;
    }
    res.set(http::field::cache_control, "no-store");
    res.set("X-Content-Type-Options", "nosniff");
    res.set("Referrer-Policy", "no-referrer");
    if (reply.media == ResponseMedia::Html) {
        res.set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
        res.set("X-Frame-Options", "DENY");
    }
    if (reply.status == 401) {
        res.set(http::field::www_authenticate, "Bearer");
    }
    res.keep_alive(keep_alive);
    res.body() = std::move(reply.body);
    res.prepare_payload();
    return res;
}

// 헤더만 보고 끝낼 수 있는 검사. 통과하면 등급이 확정된 출처를 돌려준다.
std::expected<std::pair<const Origin*, core::OpenGrade>, JsonResponse> check_headers(
    const http::request_header<>& head, Authenticator& auth, std::string_view client, audit::AuditLog* audit,
    std::uint16_t port, std::string_view credential_rotation_origin, bool credential_writer_available) {
    if (head.count(http::field::authorization) > 1) {
        return std::unexpected(error_response(EntryError::BadRequest));
    }
    const auto origin = auth.authenticate(head[http::field::authorization], client, Authenticator::Clock::now());
    if (!origin) {
        if (audit != nullptr) {
            // 기록 실패여도 응답은 같은 거절이다
            (void)audit->append("auth", "warn", {{"client", client}, {"result", auth_failure_name(origin.error())}});
        }
        return std::unexpected(error_response(origin.error() == AuthFailure::Locked ? EntryError::TooManyFailures
                                                                                     : EntryError::Unauthorized));
    }
    if (head.target() != endpoint_path && head.target() != preview_path && head.target() != approval_path &&
        head.target() != credential_rotation_path) {
        return std::unexpected(error_response(EntryError::NotFound));
    }
    if (head.method() != http::verb::post) {
        return std::unexpected(error_response(EntryError::MethodNotAllowed));
    }
    if (!is_json(head[http::field::content_type])) {
        return std::unexpected(error_response(EntryError::UnsupportedMediaType));
    }
    if (head.target() == credential_rotation_path && head.count(http::field::content_type) != 1) {
        return std::unexpected(error_response(EntryError::BadRequest));
    }
    if (head.target() == approval_path) {
        if (!local_console_request(head, client, port)) {
            if (audit != nullptr) {
                (void)audit->append("confirmation", "warn", {{"origin", (*origin)->name}, {"client", client},
                    {"result", "reject"}, {"reason", "local_only"}});
            }
            return std::unexpected(error_response(EntryError::LocalOnly));
        }
        if (head.count(confirm_header) != 0) {
            return std::unexpected(error_response(EntryError::BadRequest));
        }
    }
    if (head.target() == credential_rotation_path) {
        if (!local_console_request(head, client, port)) {
            if (audit != nullptr) {
                (void)audit->append("credential_rotation", "warn", {{"origin", (*origin)->name}, {"client", client},
                    {"result", "reject"}, {"reason", "local_only"}});
            }
            return std::unexpected(error_response(EntryError::LocalOnly));
        }
        if (credential_rotation_origin.empty() || (*origin)->name != credential_rotation_origin ||
            !credential_writer_available) {
            return std::unexpected(error_response(EntryError::NotFound));
        }
        if (head.count(confirm_header) != 0) {
            return std::unexpected(error_response(EntryError::BadRequest));
        }
    }
    // 확인 표지는 하나만, 표지 길이를 넘으면 형식 오류다(값을 기록하거나 되돌려 주지 않는다).
    if (head.count(confirm_header) > 1 || head[confirm_header].size() > confirm_token_chars ||
        (head.count(confirm_header) == 1 && head[confirm_header].empty())) {
        return std::unexpected(error_response(EntryError::BadRequest));
    }
    std::vector<std::string_view> marks;
    for (auto [it, end] = head.equal_range(grade_header); it != end; ++it) {
        marks.push_back(it->value());
    }
    auto grade = core::resolve_grade((*origin)->grade_policy, marks);
    if (!grade) {
        if (audit != nullptr) {
            // 등급 거절도 요청 결과로 남긴다(본문은 읽지 않았으므로 메타데이터만)
            (void)audit->append("request", "warn",
                                {{"origin", (*origin)->name}, {"client", client}, {"result", "reject"},
                                 {"reason", core::reason_code_name(grade.error().code())}});
        }
        return std::unexpected(error_response(grade.error().for_user()));
    }
    return std::pair{*origin, *grade};
}

std::expected<core::SensitiveText, EntryError> credential_from_json(std::string body) {
    core::SensitiveText raw(std::move(body));
    if (raw.size() > credential_rotation_body_bytes) {
        return std::unexpected(EntryError::BadRequest);
    }
    bool valid_keys = true;
    bool saw_credential = false;
    auto parsed = nlohmann::json::parse(raw.view(), [&](int depth, nlohmann::json::parse_event_t event,
                                                        nlohmann::json& value) {
        if (event == nlohmann::json::parse_event_t::key) {
            if (depth != 1 || saw_credential || !value.is_string() || value.get_ref<const std::string&>() != "credential") {
                valid_keys = false;
            }
            saw_credential = true;
        }
        return true;
    }, false);
    if (!parsed.is_object() || !parsed.contains("credential") || !parsed["credential"].is_string()) {
        return std::unexpected(EntryError::BadRequest);
    }
    auto& credential = parsed["credential"].get_ref<std::string&>();
    if (!valid_keys || parsed.size() != 1 || credential.empty() ||
        !std::ranges::all_of(credential, [](char c) { return c > 0x20 && c < 0x7f; })) {
        core::SensitiveText discarded(std::move(credential));
        return std::unexpected(EntryError::BadRequest);
    }
    return core::SensitiveText(std::move(credential));
}

JsonResponse replace_provider_credential(AcceptedRequest request, audit::AuditLog* audit,
                                         const CredentialRotationWriter& writer) {
    auto credential = credential_from_json(std::move(request.body));
    if (audit == nullptr) {
        return error_response(EntryError::Unavailable);
    }
    const auto fields = [&] {
        return nlohmann::json{{"origin", request.origin != nullptr ? request.origin->name : std::string{}},
                              {"client", request.client}};
    };
    if (!credential) {
        auto event = fields();
        event["result"] = "reject";
        event["reason"] = "bad_request";
        if (!audit->append("credential_rotation", "warn", std::move(event))) {
            return error_response(EntryError::Unavailable);
        }
        return error_response(credential.error());
    }
    auto event = fields();
    event["result"] = "attempt";
    event["reason"] = "credential_rotation";
    if (!audit->append("credential_rotation", "info", std::move(event))) {
        return error_response(EntryError::Unavailable);
    }
    bool stored = false;
    try {
        stored = writer && writer(credential->view());
    } catch (const std::exception&) {
        stored = false;
    }
    if (!stored) {
        return error_response(EntryError::Unavailable);
    }
    return JsonResponse{200, R"({"ok":true})"};
}

// 처리 중 연결이 끊기면 돌아온다. 읽을 것이 생겼는데 쌓인 바이트가 0 이면 상대가 닫은 것(FIN·RST)이다.
// 바이트가 있으면(다음 요청, TLS 종료 알림) 끊김인지 알 수 없어 처리가 끝날 때까지 기다린다.
// shortcut: TLS 종료 알림을 먼저 보내고 닫는 클라이언트는 응답을 쓸 때 끊김이 드러난다. 알림까지 읽으려면 TLS 읽기를 처리와 함께 돌려야 한다.
asio::awaitable<void> client_gone(tcp::socket& socket) {
    if (auto [ec] = co_await socket.async_wait(tcp::socket::wait_read, use_tuple); ec == asio::error::operation_aborted) {
        co_return;  // 처리가 먼저 끝났다
    }
    beast::error_code ec;
    if (socket.available(ec) == 0 || ec) {
        co_return;
    }
    asio::steady_timer until_done(co_await asio::this_coro::executor, asio::steady_timer::time_point::max());
    (void)co_await until_done.async_wait(use_tuple);
}

asio::awaitable<JsonResponse> rotate_credential(std::shared_ptr<Server::Shared> shared, AcceptedRequest request) {
    co_return replace_provider_credential(std::move(request), shared->audit, shared->credential_rotation_writer);
}

asio::awaitable<void> session(std::shared_ptr<Server::Shared> shared, tcp::socket socket) {
    struct Release {
        std::atomic<std::size_t>& count;
        ~Release() { --count; }
    } release{shared->connections};

    beast::error_code ec;
    const tcp::endpoint remote = socket.remote_endpoint(ec);
    if (ec) {
        co_return;
    }
    const std::string client = remote.address().to_string();
    Stream stream(std::move(socket), shared->tls);
    const auto deadline = [&] { beast::get_lowest_layer(stream).expires_after(shared->limits.io_timeout); };

    deadline();
    if (auto [hs] = co_await stream.async_handshake(asio::ssl::stream_base::server, use_tuple); hs) {
        co_return;  // 금지된 협상, 시간 초과 등. 응답할 수 없으므로 닫는다
    }

    beast::flat_buffer buffer;
    for (bool keep_alive = true; keep_alive;) {
        Parser parser;
        parser.header_limit(static_cast<std::uint32_t>(shared->limits.header_bytes));
        // 본문 상한은 인증 뒤에 건다. 헤더 단계에서 걸면 인증 전에 413 이 나가 상한이 드러난다.
        parser.body_limit(boost::none);
        deadline();
        auto [read_error, header_bytes] = co_await http::async_read_header(stream, buffer, parser, use_tuple);
        if (read_error) {
            if (read_error == http::error::header_limit) {
                deadline();
                (void)co_await http::async_write(
                    stream, make_reply(error_response(EntryError::BadRequest), 11, false), use_tuple);
            }
            break;
        }
        const auto& head = parser.get().base();
        const unsigned version = head.version();
        auto purpose = RequestPurpose::Chat;
        if (head.target() == preview_path) purpose = RequestPurpose::Preview;
        else if (head.target() == approval_path) purpose = RequestPurpose::Approve;
        else if (head.target() == credential_rotation_path) purpose = RequestPurpose::CredentialRotation;
        auto body_limit = shared->limits.body_bytes;
        if (purpose == RequestPurpose::Approve) body_limit = std::min(body_limit, confirm_body_bytes);
        if (purpose == RequestPurpose::CredentialRotation) {
            body_limit = std::min(body_limit, credential_rotation_body_bytes);
        }

        std::optional<JsonResponse> reply;
        std::shared_ptr<UploadLease> upload;
        std::string request_body;
        BodyCleanup cleanup{request_body};
        auto resource = console_resource(head, client, shared->port);
        std::optional<std::pair<const Origin*, core::OpenGrade>> accepted;
        if (resource) {
            reply = std::move(*resource);
        } else {
            auto checked = check_headers(head, shared->auth, client, shared->audit, shared->port,
                                         shared->credential_rotation_origin,
                                         static_cast<bool>(shared->credential_rotation_writer));
            if (checked) accepted.emplace(*checked);
            else reply = std::move(checked.error());
        }
        if (const auto length = parser.content_length(); !reply && length && *length > body_limit) {
            reply = error_response(EntryError::BodyTooLarge);
        }
        if (!reply) {
            parser.body_limit(body_limit);
            if (const auto length = parser.content_length(); length && *length > core::max_prompt_bytes) {
                upload = reserve_large_upload(shared);
                if (!upload) reply = error_response(EntryError::Overloaded);
            }
            deadline();
            std::array<char, 16 * 1024> chunk{};
            struct ChunkCleanup {
                std::span<char> bytes;
                ~ChunkCleanup() { core::secure_wipe(bytes); }
            } clear_chunk{chunk};
            while (!reply && !parser.is_done()) {
                parser.get().body().data = chunk.data();
                parser.get().body().size = chunk.size();
                auto [body_error, body_bytes] = co_await http::async_read_some(stream, buffer, parser, use_tuple);
                const auto consumed = chunk.size() - parser.get().body().size;
                if (body_error == http::error::body_limit ||
                    consumed > body_limit - request_body.size()) {
                    reply = error_response(EntryError::BodyTooLarge);
                    break;
                }
                if (body_error && body_error != http::error::need_buffer) co_return;
                if (!upload && request_body.size() + consumed > core::max_prompt_bytes) {
                    upload = reserve_large_upload(shared);
                    if (!upload) {
                        reply = error_response(EntryError::Overloaded);
                        break;
                    }
                }
                request_body.append(chunk.data(), consumed);
                core::secure_wipe(chunk);
            }
            if (!reply) {
                using namespace asio::experimental::awaitable_operators;
                try {
                    // 처리 중 연결이 끊기면 처리 단계에 asio 취소를 보내 남은 단계를 멈추고 가명 범위를 지우게 한다
                    auto accepted_request = AcceptedRequest{accepted->first, accepted->second,
                                                            std::move(request_body), client,
                                                            std::string(head[confirm_header]), std::move(upload), purpose};
                    auto operation = purpose == RequestPurpose::CredentialRotation
                        ? rotate_credential(shared, std::move(accepted_request))
                        : shared->handler(std::move(accepted_request));
                    auto outcome = co_await (std::move(operation) ||
                                             client_gone(beast::get_lowest_layer(stream).socket()));
                    if (outcome.index() == 1) {
                        co_return;  // 받을 사람이 없다
                    }
                    reply = std::move(std::get<0>(outcome));
                } catch (const std::exception&) {
                    reply = error_response(core::UserRejection{core::ReasonCode::InternalError, {}});
                }
            }
        }
        // 거절하면 연결을 닫는다(읽지 않은 본문이 남아 있을 수 있다)
        const bool rejected = reply->status >= 400;
        if (shared->chat_app_compat && purpose == RequestPurpose::Chat && !resource) {
            *reply = chat_notice(std::move(*reply), shared->port);
        }
        keep_alive = !resource && !rejected && parser.get().keep_alive();
        deadline();
        if (auto [write_error, written] =
                co_await http::async_write(stream, make_reply(std::move(*reply), version, keep_alive), use_tuple);
            write_error) {
            co_return;
        }
    }
    deadline();
    (void)co_await stream.async_shutdown(use_tuple);
}

asio::awaitable<void> accept_loop(std::shared_ptr<Server::Shared> shared) {
    for (;;) {
        auto [ec, socket] = co_await shared->acceptor.async_accept(use_tuple);
        if (ec == asio::error::operation_aborted || !shared->acceptor.is_open()) {
            co_return;
        }
        if (ec) {
            continue;
        }
        if (shared->connections.load() >= shared->limits.max_connections) {
            beast::error_code ignored;
            socket.close(ignored);
            continue;
        }
        ++shared->connections;
        // 연결 하나의 일(읽기·쓰기·처리·취소 신호)은 strand 하나에서 차례로 돈다
        asio::co_spawn(asio::make_strand(shared->acceptor.get_executor()), session(shared, std::move(socket)),
                       asio::detached);
    }
}

}  // namespace

Server::Server(asio::io_context& io, asio::ssl::context& tls, const tcp::endpoint& endpoint, Authenticator& auth,
               RequestHandler handler, ServerLimits limits, audit::AuditLog* audit, bool chat_app_compat,
               std::string credential_rotation_origin, CredentialRotationWriter credential_rotation_writer)
    : shared_(std::make_shared<Shared>(io, tls, endpoint, auth, std::move(handler), limits, audit, chat_app_compat,
                                       std::move(credential_rotation_origin), std::move(credential_rotation_writer))) {}

void Server::start() { asio::co_spawn(shared_->acceptor.get_executor(), accept_loop(shared_), asio::detached); }

void Server::stop() {
    asio::post(shared_->acceptor.get_executor(), [shared = shared_] {
        beast::error_code ignored;
        shared->acceptor.close(ignored);
    });
}

tcp::endpoint Server::local_endpoint() const { return shared_->acceptor.local_endpoint(); }

}  // namespace prompt_airlock::gateway
