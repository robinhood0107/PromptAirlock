#include "prompt_airlock/ner/sha256.hpp"

#include <algorithm>
#include <bit>

namespace prompt_airlock::ner {
namespace {

constexpr std::array<std::uint32_t, 64> round_constants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

}  // namespace

void Sha256::compress(const std::byte* block) noexcept {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = (std::uint32_t{std::to_integer<std::uint8_t>(block[4 * i])} << 24) |
               (std::uint32_t{std::to_integer<std::uint8_t>(block[4 * i + 1])} << 16) |
               (std::uint32_t{std::to_integer<std::uint8_t>(block[4 * i + 2])} << 8) |
               std::uint32_t{std::to_integer<std::uint8_t>(block[4 * i + 3])};
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const auto s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const auto s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    auto [a, b, c, d, e, f, g, h] = state_;
    for (std::size_t i = 0; i < 64; ++i) {
        const auto big1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
        const auto choose = (e & f) ^ (~e & g);
        const auto t1 = h + big1 + choose + round_constants[i] + w[i];
        const auto big0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
        const auto majority = (a & b) ^ (a & c) ^ (b & c);
        const auto t2 = big0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    const std::array<std::uint32_t, 8> added{a, b, c, d, e, f, g, h};
    for (std::size_t i = 0; i < 8; ++i) {
        state_[i] += added[i];
    }
}

void Sha256::update(std::span<const std::byte> data) noexcept {
    total_bytes_ += data.size();
    while (!data.empty()) {
        const auto take = std::min(data.size(), buffer_.size() - buffered_);
        std::copy_n(data.begin(), take, buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_));
        buffered_ += take;
        data = data.subspan(take);
        if (buffered_ == buffer_.size()) {
            compress(buffer_.data());
            buffered_ = 0;
        }
    }
}

std::string Sha256::finish_hex() noexcept {
    const std::uint64_t bit_length = total_bytes_ * 8;
    // 0x80 하나, 길이 8 byte 가 들어갈 자리가 남을 때까지 0 으로 채운다.
    std::array<std::byte, 72> padding{};
    padding[0] = std::byte{0x80};
    const auto zeros = (buffered_ < 56 ? 56 : 120) - buffered_;
    for (std::size_t i = 0; i < 8; ++i) {
        padding[zeros + i] = static_cast<std::byte>(bit_length >> (56 - 8 * i));
    }
    update(std::span<const std::byte>(padding).first(zeros + 8));

    constexpr std::string_view digits = "0123456789abcdef";
    std::string hex;
    hex.reserve(64);
    for (const auto word : state_) {
        for (int shift = 28; shift >= 0; shift -= 4) {
            hex.push_back(digits[(word >> shift) & 0xF]);
        }
    }
    return hex;
}

std::string sha256_hex(std::span<const std::byte> data) {
    Sha256 hash;
    hash.update(data);
    return hash.finish_hex();
}

}  // namespace prompt_airlock::ner
