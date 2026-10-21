// SHA-256 직접 구현: 표준 시험 벡터(FIPS 180-4, NIST)와 조각 입력 일치.
#include "prompt_airlock/ner/sha256.hpp"

#include <gtest/gtest.h>

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pn = prompt_airlock::ner;

namespace {

std::vector<std::byte> bytes_of(std::string_view s) {
    std::vector<std::byte> out;
    out.reserve(s.size());
    for (const char c : s) {
        out.push_back(static_cast<std::byte>(c));
    }
    return out;
}

}  // namespace

TEST(NerSha256, StandardVectors) {
    EXPECT_EQ(pn::sha256_hex(bytes_of("")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(pn::sha256_hex(bytes_of("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(pn::sha256_hex(bytes_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    EXPECT_EQ(pn::sha256_hex(bytes_of("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")),
              "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

TEST(NerSha256, MillionAs) {
    pn::Sha256 hash;
    const std::vector<std::byte> chunk(1000, std::byte{'a'});
    for (int i = 0; i < 1000; ++i) {
        hash.update(chunk);
    }
    EXPECT_EQ(hash.finish_hex(), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// 블록 경계(55, 56, 63, 64, 65 byte)는 패딩이 달라지는 자리다. 한 번에 넣은 값과 한 byte씩 넣은 값이 같아야 한다.
TEST(NerSha256, PaddingBoundariesAndChunkingAgree) {
    for (const std::size_t n : {0u, 1u, 55u, 56u, 57u, 63u, 64u, 65u, 119u, 120u, 128u}) {
        const std::vector<std::byte> data(n, std::byte{0x5a});
        pn::Sha256 byte_by_byte;
        for (const auto b : data) {
            byte_by_byte.update(std::span(&b, 1));
        }
        EXPECT_EQ(byte_by_byte.finish_hex(), pn::sha256_hex(data)) << n;
    }
}
