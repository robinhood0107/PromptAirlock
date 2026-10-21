// 출처 인증(ADR 0020). Authorization: Bearer <token> 의 SHA-256 을 등록된 값과 상수 시간으로 비교한다.
// 같은 접속 주소에서 실패가 이어지면 그 주소를 잠시 잠근다. 여러 연결이 함께 부르므로 내부에서 잠근다.
#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "prompt_airlock/gateway/config.hpp"

namespace prompt_airlock::gateway {

enum class AuthFailure : std::uint8_t {
    Missing,    // 헤더 없음
    Malformed,  // Bearer 형식이 아님
    Unknown,    // 등록되지 않은 token
    Locked,     // 실패가 이어져 잠긴 접속 주소
};

class Authenticator {
public:
    using Clock = std::chrono::steady_clock;

    static constexpr int max_failures = 5;
    static constexpr std::chrono::seconds lock_duration{60};
    static constexpr std::size_t max_tracked_clients = 4096;

    explicit Authenticator(std::vector<Origin> origins);

    // 성공하면 등록 출처를 가리킨다(Authenticator 가 살아 있는 동안만 유효).
    // authorization 은 헤더 값 전체이고, 없으면 빈 값이다. client 는 접속 주소 문자열이다.
    [[nodiscard]] std::expected<const Origin*, AuthFailure> authenticate(std::string_view authorization,
                                                                         std::string_view client,
                                                                         Clock::time_point now);

private:
    struct Failures {
        int count = 0;
        Clock::time_point locked_until{};
    };
    void record_failure(const std::string& client, Clock::time_point now);

    std::vector<Origin> origins_;
    std::mutex mutex_;
    std::unordered_map<std::string, Failures> failures_;
};

[[nodiscard]] std::string_view auth_failure_name(AuthFailure failure) noexcept;

}  // namespace prompt_airlock::gateway
