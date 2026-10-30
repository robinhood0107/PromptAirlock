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

#include <atomic>
#include <exception>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

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
           RequestHandler request_handler, ServerLimits server_limits, audit::AuditLog* audit_log)
        : tls(tls_context),
          acceptor(io, endpoint, reuse_address),
          auth(authenticator),
          handler(std::move(request_handler)),
          limits(server_limits),
          audit(audit_log) {}

    asio::ssl::context& tls;
    tcp::acceptor acceptor;
    Authenticator& auth;
    RequestHandler handler;
    ServerLimits limits;
    audit::AuditLog* audit;
    std::atomic<std::size_t> connections{0};
};

namespace {

using Stream = beast::ssl_stream<beast::tcp_stream>;
using Parser = http::request_parser<http::string_body>;
constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);

constexpr std::string_view endpoint_path = "/v1/chat/completions";
constexpr std::string_view grade_header = "X-Prompt-Airlock-Grade";  // ADR 0013

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
    res.set(http::field::content_type, "application/json");
    res.set(http::field::cache_control, "no-store");
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
    const http::request_header<>& head, Authenticator& auth, std::string_view client, audit::AuditLog* audit) {
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
    if (head.target() != endpoint_path) {
        return std::unexpected(error_response(EntryError::NotFound));
    }
    if (head.method() != http::verb::post) {
        return std::unexpected(error_response(EntryError::MethodNotAllowed));
    }
    if (!is_json(head[http::field::content_type])) {
        return std::unexpected(error_response(EntryError::UnsupportedMediaType));
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

        std::optional<JsonResponse> reply;
        auto accepted = check_headers(head, shared->auth, client, shared->audit);
        if (!accepted) {
            reply = std::move(accepted.error());
        } else if (const auto length = parser.content_length(); length && *length > shared->limits.body_bytes) {
            reply = error_response(EntryError::BodyTooLarge);
        } else {
            parser.body_limit(shared->limits.body_bytes);  // chunked 본문은 읽으면서 센다
            deadline();
            auto [body_error, body_bytes] = co_await http::async_read(stream, buffer, parser, use_tuple);
            if (body_error == http::error::body_limit) {
                reply = error_response(EntryError::BodyTooLarge);
            } else if (body_error) {
                break;
            } else {
                using namespace asio::experimental::awaitable_operators;
                try {
                    // 처리 중 연결이 끊기면 처리 단계에 asio 취소를 보내 남은 단계를 멈추고 가명 범위를 지우게 한다
                    auto outcome = co_await (shared->handler(AcceptedRequest{accepted->first, accepted->second,
                                                                             std::move(parser.get().body()), client}) ||
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
        keep_alive = reply->status < 400 && parser.get().keep_alive();
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
               RequestHandler handler, ServerLimits limits, audit::AuditLog* audit)
    : shared_(std::make_shared<Shared>(io, tls, endpoint, auth, std::move(handler), limits, audit)) {}

void Server::start() { asio::co_spawn(shared_->acceptor.get_executor(), accept_loop(shared_), asio::detached); }

void Server::stop() {
    asio::post(shared_->acceptor.get_executor(), [shared = shared_] {
        beast::error_code ignored;
        shared->acceptor.close(ignored);
    });
}

tcp::endpoint Server::local_endpoint() const { return shared_->acceptor.local_endpoint(); }

}  // namespace prompt_airlock::gateway
