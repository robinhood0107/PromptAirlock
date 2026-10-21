// SHA-256(FIPS 180-4). 고정 파일 확인(NER 모델), 출처 token 대조, 감사 연결 해시에 쓴다. 입출력 없는 순수 계산이다.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace prompt_airlock::core {

class Sha256 {
public:
    void update(std::span<const std::byte> data) noexcept;
    // 소문자 16진수 64자. 한 번만 부른다(부른 뒤에는 update 하지 않는다).
    [[nodiscard]] std::string finish_hex() noexcept;

private:
    void compress(const std::byte* block) noexcept;

    std::array<std::uint32_t, 8> state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::array<std::byte, 64> buffer_{};
    std::size_t buffered_ = 0;
    std::uint64_t total_bytes_ = 0;
};

[[nodiscard]] std::string sha256_hex(std::span<const std::byte> data);

}  // namespace prompt_airlock::core
