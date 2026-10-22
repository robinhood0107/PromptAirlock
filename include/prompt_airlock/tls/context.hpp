// TLS 설정(ADR 0014). OpenSSL 을 직접 부르는 곳은 이 모듈뿐이다.
// 협상 범위는 고정이고 설정으로 바꿀 수 없다: TLS 1.2·1.3, AES-GCM, ECDHE(P-256·P-384), ECDSA·RSA-PSS 서명.
#pragma once

#include <boost/asio/ssl/context.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>

namespace prompt_airlock::tls {

enum class TlsError : std::uint8_t {
    Setup,               // OpenSSL 이 고정 협상 범위를 받아들이지 않음
    InvalidCertificate,  // 인증서 체인 PEM 을 읽을 수 없음
    InvalidKey,          // 개인키 PEM 을 읽을 수 없거나 키 쌍이 맞지 않음
    WeakKey,             // RSA 2048비트 미만, 또는 P-256·P-384 가 아닌 EC 키
    InvalidTrustStore,   // 신뢰할 인증기관 PEM 을 읽을 수 없음
};

// 기관 앱 방향(수신) 서버. 인증서 체인과 개인키는 PEM 바이트(파일을 읽는 것은 호출자).
[[nodiscard]] std::expected<boost::asio::ssl::context, TlsError> make_server_context(std::string_view certificate_chain_pem,
                                                                                    std::string_view private_key_pem);

// provider 방향(송신) 클라이언트. 상대 인증서를 항상 검증한다. trust_pem 이 없으면 운영체제 기본 저장소를 쓴다.
// 호스트 이름 확인과 SNI 는 연결하는 쪽(provider 클라이언트)이 정한다.
[[nodiscard]] std::expected<boost::asio::ssl::context, TlsError> make_client_context(
    std::optional<std::string_view> trust_pem);

// 인증서 체인 첫 인증서의 만료까지 남은 날(지났으면 음수). 읽을 수 없으면 nullopt. 만료 경고(ADR 0021)에 쓴다.
[[nodiscard]] std::optional<int> certificate_days_left(std::string_view certificate_chain_pem);

}  // namespace prompt_airlock::tls
