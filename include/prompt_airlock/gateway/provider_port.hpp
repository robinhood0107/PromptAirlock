// provider 호출 경계. 게이트웨이가 정하고 provider 클라이언트가 구현한다(provider 는 요청 처리 단계를 몰라도 된다).
#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstdint>
#include <expected>
#include <functional>
#include <string>

namespace prompt_airlock::gateway {

struct ProviderReply {
    unsigned status;
    std::string body;
};

enum class ProviderError : std::uint8_t { Unavailable, Timeout, BadResponse };

// provider 호출. 검증된 요청 본문만 받는다. 주소와 자격 증명은 구현(provider 클라이언트)이 가진다.
using ProviderCall =
    std::function<boost::asio::awaitable<std::expected<ProviderReply, ProviderError>>(std::string body)>;

}  // namespace prompt_airlock::gateway
