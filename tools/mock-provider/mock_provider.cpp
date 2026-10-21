#include "mock_provider.hpp"

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>

#include <fstream>
#include <mutex>
#include <utility>

#include "../../src/gateway/role_name.hpp"

namespace pa_mock {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
using json = nlohmann::json;

struct MockProvider::State {
    State(asio::io_context& io, asio::ssl::context& tls_context, const tcp::endpoint& endpoint, MockOptions opts)
        : tls(tls_context), acceptor(io, endpoint), options(std::move(opts)) {}

    void record(const std::string& body) {
        std::scoped_lock lock(mutex);
        bodies.push_back(body);
        if (!options.record_file.empty()) {
            std::ofstream(options.record_file, std::ios::app | std::ios::binary) << body << '\n';
        }
    }

    asio::ssl::context& tls;
    tcp::acceptor acceptor;
    MockOptions options;
    mutable std::mutex mutex;
    std::vector<std::string> bodies;
};

namespace {

constexpr auto use_tuple = asio::as_tuple(asio::use_awaitable);
using prompt_airlock::core::MessageRole;
using prompt_airlock::gateway::detail::role_name;

// 마지막 user 메시지의 텍스트(문자열 또는 text part 를 이은 것).
std::string last_user_text(const json& request) {
    std::string text;
    for (const auto& message : request.value("messages", json::array())) {
        if (message.value("role", "") != role_name(MessageRole::User)) {
            continue;
        }
        text.clear();
        const auto& content = message["content"];
        if (content.is_string()) {
            text = content.get<std::string>();
        } else if (content.is_array()) {
            for (const auto& part : content) {
                text += part.value("text", "");
            }
        }
    }
    return text;
}

http::response<http::string_body> reply(http::status status, std::string body) {
    http::response<http::string_body> res{status, 11};
    res.set(http::field::content_type, "application/json");
    res.keep_alive(false);
    res.body() = std::move(body);
    res.prepare_payload();
    return res;
}

asio::awaitable<void> session(std::shared_ptr<MockProvider::State> state, tcp::socket socket) {
    beast::ssl_stream<beast::tcp_stream> stream(std::move(socket), state->tls);
    beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
    if (auto [ec] = co_await stream.async_handshake(asio::ssl::stream_base::server, use_tuple); ec) {
        co_return;
    }
    beast::flat_buffer buffer;
    http::request<http::string_body> req;
    if (auto [ec, n] = co_await http::async_read(stream, buffer, req, use_tuple); ec) {
        co_return;
    }
    http::response<http::string_body> res;
    if (req[http::field::authorization] != "Bearer " + state->options.credential) {
        res = reply(http::status::unauthorized, R"({"error":{"message":"bad key","type":"invalid_request_error"}})");
    } else {
        state->record(req.body());
        res = reply(http::status::ok, make_answer(req.body()));
    }
    (void)co_await http::async_write(stream, res, use_tuple);
    (void)co_await stream.async_shutdown(use_tuple);
}

asio::awaitable<void> accept_loop(std::shared_ptr<MockProvider::State> state) {
    for (;;) {
        auto [ec, socket] = co_await state->acceptor.async_accept(use_tuple);
        if (ec == asio::error::operation_aborted || !state->acceptor.is_open()) {
            co_return;
        }
        if (!ec) {
            asio::co_spawn(state->acceptor.get_executor(), session(state, std::move(socket)), asio::detached);
        }
    }
}

}  // namespace

std::string make_answer(const std::string& request_body) {
    const json request = json::parse(request_body, nullptr, /*allow_exceptions=*/false);
    const std::string question = request.is_object() ? last_user_text(request) : std::string();
    const json answer = {
        {"id", "mock-1"},
        {"object", "chat.completion"},
        {"model", request.is_object() ? request.value("model", "") : ""},
        {"choices", json::array({{{"index", 0},
                                  {"message", {{"role", role_name(MessageRole::Model)}, {"content", "받은 질문: " + question}}},
                                  {"finish_reason", "stop"}}})},
        {"usage", {{"prompt_tokens", 0}, {"completion_tokens", 0}, {"total_tokens", 0}}},
    };
    return answer.dump();
}

MockProvider::MockProvider(asio::io_context& io, asio::ssl::context& tls, const tcp::endpoint& endpoint,
                           MockOptions options)
    : state_(std::make_shared<State>(io, tls, endpoint, std::move(options))) {}

void MockProvider::start() { asio::co_spawn(state_->acceptor.get_executor(), accept_loop(state_), asio::detached); }

void MockProvider::stop() {
    asio::post(state_->acceptor.get_executor(), [state = state_] {
        beast::error_code ignored;
        state->acceptor.close(ignored);
    });
}

tcp::endpoint MockProvider::local_endpoint() const { return state_->acceptor.local_endpoint(); }

std::vector<std::string> MockProvider::received() const {
    std::scoped_lock lock(state_->mutex);
    return state_->bodies;
}

}  // namespace pa_mock
