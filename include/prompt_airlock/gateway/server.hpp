// HTTPS 입구(ADR 0004, 0020). POST /v1/chat/completions 하나만 받는다.
// 순서: TLS → 헤더 읽기 → 출처 인증 → 경로·메서드·형식 → 등급 헤더 → 본문(상한) → handler.
// 앞 단계에서 거절하면 본문은 읽지 않고, handler(그 뒤 provider)는 불리지 않는다.
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>

#include "prompt_airlock/audit/log.hpp"
#include "prompt_airlock/core/grade.hpp"
#include "prompt_airlock/gateway/auth.hpp"
#include "prompt_airlock/gateway/error_body.hpp"

namespace prompt_airlock::gateway {

struct ServerLimits {
    std::size_t header_bytes = 8 * 1024;
    std::size_t body_bytes = 64 * 1024;
    std::chrono::seconds io_timeout{10};  // TLS handshake, 헤더, 본문, 응답 쓰기 각각
    std::size_t max_connections = 256;    // 넘으면 새 연결을 바로 닫는다
};

// 인증과 등급 확정까지 통과한 요청. origin 은 Authenticator 가 가진 값을 가리킨다.
struct AcceptedRequest {
    const Origin* origin;
    core::OpenGrade grade;
    std::string body;
    std::string client;   // 접속 주소(감사 기록용)
    std::string confirm;  // 경고 확인 표지(X-Prompt-Airlock-Confirm, ADR 0023). 없으면 빈 문자열
};

// 요청 처리. 여러 연결이 함께 부르므로 스레드 안전해야 한다.
using RequestHandler = std::function<boost::asio::awaitable<JsonResponse>(AcceptedRequest)>;

class Server {
public:
    // tls, auth, handler, audit 는 Server 보다 오래 살아야 한다. audit 가 있으면 인증 실패를 남긴다.
    Server(boost::asio::io_context& io, boost::asio::ssl::context& tls, const boost::asio::ip::tcp::endpoint& endpoint,
           Authenticator& auth, RequestHandler handler, ServerLimits limits = {}, audit::AuditLog* audit = nullptr);

    // 연결 받기를 시작한다. 실제 처리는 io 를 돌리는 스레드에서 한다.
    void start();
    void stop();
    [[nodiscard]] boost::asio::ip::tcp::endpoint local_endpoint() const;

    struct Shared;  // 구현 세부. 연결 coroutine 들이 함께 쓴다

private:
    std::shared_ptr<Shared> shared_;
};

}  // namespace prompt_airlock::gateway
