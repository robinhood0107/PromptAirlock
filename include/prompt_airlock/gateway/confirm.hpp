// 경고 모드 확인 표지(ADR 0023). 판별기만 걸린 요청에 표지를 주고, 사용자가 같은 본문에 표지를 붙여 다시 보내면 한 번 통과시킨다.
// 표지는 본문 SHA-256과 인증 출처에 묶인다. 같은 출처에서 한 번 쓰면(맞든 틀리든) 없어지며 기한을 넘기면 쓸 수 없다.
#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace prompt_airlock::gateway {

inline constexpr std::chrono::minutes confirm_ttl{5};
// 동시에 살아 있는 표지 수 상한. 다 차면 새 표지를 주지 않는다(요청은 거절, fail closed).
inline constexpr std::size_t confirm_capacity = 1024;
// 표지 길이(16진수). 128 bit.
inline constexpr std::size_t confirm_token_chars = 32;
inline constexpr std::size_t confirm_body_bytes = 1024;
[[nodiscard]] bool valid_confirmation_token(std::string_view token) noexcept;

class ConfirmLedger {
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    // 시계는 잠금 안에서 읽는다. 주입 함수는 스레드 안전해야 하며 장부를 다시 부르면 안 된다.
    explicit ConfirmLedger(Now now = Clock::now) : now_(std::move(now)) {}

    // body_sha256 에 묶인 새 표지. 상한에 닿아 줄 수 없으면 nullopt.
    [[nodiscard]] std::optional<std::string> issue(std::string_view body_sha256, std::string_view origin);
    // 같은 출처의 표지가 기한 안이고 같은 본문이면 true. 그 출처의 시도는 결과와 상관없이 소모한다.
    [[nodiscard]] bool redeem(std::string_view token, std::string_view body_sha256, std::string_view origin);
    // 검사와 승인 사이에 다른 요청이 표지를 쓰지 못하게 같은 잠금 안에서 감사·취소 검사를 마친다.
    // check의 해시 뷰는 호출 중에만 유효하며, check에서 장부를 다시 부르면 안 된다.
    [[nodiscard]] bool approve(std::string_view token, std::string_view origin,
                                const std::function<bool(std::string_view)>& check);
    [[nodiscard]] bool redeem_approved(std::string_view body_sha256, std::string_view origin);

private:
    enum class State { Pending, Approved };
    struct Entry {
        std::string body_sha256;
        std::string origin;
        Clock::time_point expires;
        State state = State::Pending;
    };
    const Now now_;
    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
};

}  // namespace prompt_airlock::gateway
