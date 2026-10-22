// provider HTTPS 클라이언트(Chat Completions 호환). provider 주소와 자격 증명은 이 계층만 가진다.
// 요청마다 연결을 새로 열고(TLS 검증 포함) 응답을 받은 뒤 닫는다. 클라이언트 요청 헤더는 넘기지 않는다.
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>

#include "prompt_airlock/core/sensitive.hpp"
#include "prompt_airlock/gateway/pipeline.hpp"

namespace prompt_airlock::provider {

struct Endpoint {
    std::string host;
    std::uint16_t port = 443;
    std::string target;
};

struct ClientLimits {
    std::chrono::seconds timeout{120};  // 연결부터 응답 끝까지
    std::size_t response_bytes = 1024 * 1024;
};

enum class CredentialError : std::uint8_t { Unreadable, Empty, InvalidCharacter, NotProtected };

// 자격 증명 파일(ADR 0021). Windows 는 DPAPI(현재 사용자)로 보호한 파일만, Linux 는 권한 0600(그룹·다른 사용자 권한 없음) 파일만 읽는다.
// 내용은 한 줄(끝 줄바꿈은 뗀다), 보이는 ASCII 만(헤더에 그대로 들어가므로).
[[nodiscard]] std::expected<core::SensitiveText, CredentialError> load_credential(const std::filesystem::path& path);

// 평문 자격 증명을 파일에 쓸 바이트로 바꾼다. Windows 는 DPAPI 로 암호화하고, Linux 는 그대로 둔다(쓰는 쪽이 0600 으로 쓴다).
[[nodiscard]] std::expected<std::string, CredentialError> protect_credential(std::string_view plain);

class HttpsClient {
public:
    // tls 는 make_client_context 로 만든 것이고 HttpsClient 보다 오래 살아야 한다.
    HttpsClient(boost::asio::ssl::context& tls, Endpoint endpoint, core::SensitiveText credential,
                ClientLimits limits = {});

    // 여러 요청이 함께 불러도 된다(상태를 바꾸지 않는다).
    [[nodiscard]] boost::asio::awaitable<std::expected<gateway::ProviderReply, gateway::ProviderError>> send(
        std::string body) const;

private:
    boost::asio::ssl::context& tls_;
    Endpoint endpoint_;
    core::SensitiveText credential_;
    ClientLimits limits_;
};

}  // namespace prompt_airlock::provider
