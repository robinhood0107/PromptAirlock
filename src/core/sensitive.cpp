#include "prompt_airlock/core/sensitive.hpp"

#include <atomic>
#include <utility>

namespace prompt_airlock::core {
namespace {

// 문자열의 할당된 전체 영역(SSO 포함)을 지우고 비운다. capacity 안에서만 늘리므로 재할당하지 않는다.
void wipe(std::string& value) noexcept {
    value.resize(value.capacity());
    secure_wipe(std::span<char>(value.data(), value.size()));
    value.clear();
}

}  // namespace

void secure_wipe(std::span<char> bytes) noexcept {
    volatile char* out = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        out[i] = 0;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

SensitiveText::SensitiveText(std::string&& value) noexcept : value_(std::move(value)) {
    // SSO 크기 문자열은 이동해도 원본에 바이트가 남는다.
    wipe(value);
}

SensitiveText SensitiveText::copy_of(std::string_view value) {
    std::string copy;
    copy.reserve(value.size());
    copy.assign(value);
    return SensitiveText(std::move(copy));
}

SensitiveText::SensitiveText(SensitiveText&& other) noexcept : value_(std::move(other.value_)) {
    wipe(other.value_);
}

SensitiveText& SensitiveText::operator=(SensitiveText&& other) noexcept {
    if (this != &other) {
        wipe(value_);
        value_ = std::move(other.value_);
        wipe(other.value_);
    }
    return *this;
}

SensitiveText::~SensitiveText() { wipe(value_); }

}  // namespace prompt_airlock::core
