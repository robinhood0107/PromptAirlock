#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/reason.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// 몇 단계 풀었는가. 1 또는 2(ADR 0017 10번).
class DecodeDepth {
public:
    [[nodiscard]] static constexpr std::expected<DecodeDepth, InputError> make(std::uint8_t value) noexcept {
        if (value < 1 || value > 2) {
            return std::unexpected(InputError::ValueOutOfRange);
        }
        return DecodeDepth(value);
    }
    [[nodiscard]] constexpr std::uint8_t value() const noexcept { return value_; }
    constexpr bool operator==(const DecodeDepth&) const noexcept = default;

private:
    constexpr explicit DecodeDepth(std::uint8_t value) noexcept : value_(value) {}
    std::uint8_t value_;
};

// 인코딩 덩어리 하나를 풀어 본 결과. 실제로 푸는 decoder 는 Phase 5 가 만든다.
struct EncodedFinding {
    SegmentIndex segment;
    ByteSpan source;         // 원래 덩어리의 위치
    EncodingKind kind;
    DecodeDepth depth;
    bool decoded_is_text;    // 푼 결과가 UTF-8 텍스트인가
    bool still_encoded;      // 깊이 2 까지 풀어도 다시 인코딩으로 보이는가
    EntityTypeSet targets;   // 푼 결과에서 찾은 가명화·차단 종류
};

// 확인할 수 없는 덩어리의 최소 길이. 원래 덩어리의 byte 길이이며, 인코딩은 ASCII 라 글자 수와 같다.
inline constexpr std::size_t opaque_blob_min_bytes = 256;

// 1) 푼 결과에서 대상이 하나라도 나오면 EncodedTarget(인코딩 안의 값은 가명으로 바꾸지 않는다).
// 2) 텍스트가 아니거나 깊이 2 뒤에도 인코딩인 덩어리가 256 byte 이상이면 OpaqueEncodedBlob.
// 3) 그 밖에는 통과(짧은 해시값 등). 사용자에게는 코드만, 위치·인코딩 종류는 감사에만 남긴다.
[[nodiscard]] std::expected<void, Rejection> judge_encoded(std::span<const EncodedFinding> findings);

}  // namespace prompt_airlock::core
