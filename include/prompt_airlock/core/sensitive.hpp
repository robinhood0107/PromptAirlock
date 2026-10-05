#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

#include "prompt_airlock/core/detail/attributes.hpp"

namespace prompt_airlock::core {

// 바이트를 0 으로 덮는다. 최적화로 지워지지 않도록 volatile 쓰기와 signal fence 를 쓴다.
// 표준이 보장하는 지우기 API 가 없어 최선 노력이며, 레지스터·스왑·할당자 내부 사본은 지우지 못한다.
void secure_wipe(std::span<char> bytes) noexcept;

// 원문이나 가명 상태 본문을 담는 상자. 복사할 수 없고, 소멸·이동 때 버퍼를 지운다.
// std::string 이 커지며 버린 이전 버퍼는 지울 수 없으므로 한 번 받은 내용에 다시 덧붙이지 않는다.
// 출력 연산자와 std::formatter 는 일부러 두지 않는다(로그로 새지 않게).
class SensitiveText {
public:
    SensitiveText() noexcept = default;
    // 소유권만 넘겨받는다. 넘겨준 문자열의 SSO 영역까지 지운다.
    explicit SensitiveText(std::string&& value) noexcept;
    // 복사가 필요하면 이름 붙은 함수로만 만든다.
    [[nodiscard]] static SensitiveText copy_of(std::string_view value);

    SensitiveText(const SensitiveText&) = delete;
    SensitiveText& operator=(const SensitiveText&) = delete;
    SensitiveText(SensitiveText&& other) noexcept;
    SensitiveText& operator=(SensitiveText&& other) noexcept;
    ~SensitiveText();

    [[nodiscard]] std::string_view view() const& noexcept PA_LIFETIMEBOUND { return value_; }
    std::string_view view() const&& = delete;

    [[nodiscard]] std::size_t size() const noexcept { return value_.size(); }
    [[nodiscard]] bool empty() const noexcept { return value_.empty(); }

private:
    std::string value_;
};

}  // namespace prompt_airlock::core
