// 경고 모드 확인 표지(ADR 0023). 판별기만 걸린 요청에 표지를 주고, 사용자가 같은 본문에 표지를 붙여 다시 보내면 한 번 통과시킨다.
// 표지는 본문 SHA-256 에 묶이고, 한 번 쓰면(맞든 틀리든) 없어지며, confirm_ttl 이 지나면 쓸 수 없다. 메모리에만 둔다.
#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace prompt_airlock::gateway {

inline constexpr std::chrono::minutes confirm_ttl{5};
// 동시에 살아 있는 표지 수 상한. 다 차면 새 표지를 주지 않는다(요청은 거절, fail closed).
inline constexpr std::size_t confirm_capacity = 1024;
// 표지 길이(16진수). 128 bit.
inline constexpr std::size_t confirm_token_chars = 32;

class ConfirmLedger {
public:
    using Clock = std::chrono::steady_clock;

    // body_sha256 에 묶인 새 표지. 상한에 닿아 줄 수 없으면 nullopt.
    [[nodiscard]] std::optional<std::string> issue(std::string_view body_sha256, Clock::time_point now);
    // 표지가 있고, 기한 안이고, 같은 본문이면 true. 찾은 표지는 결과와 상관없이 지운다.
    [[nodiscard]] bool redeem(std::string_view token, std::string_view body_sha256, Clock::time_point now);

private:
    struct Entry {
        std::string body_sha256;
        Clock::time_point expires;
    };
    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
};

}  // namespace prompt_airlock::gateway
