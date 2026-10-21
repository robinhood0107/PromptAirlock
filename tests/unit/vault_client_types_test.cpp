// 인증 비밀값 AuthSecret 의 이동 규칙: 옮긴 쪽은 지워지고, 자기 이동은 값을 잃지 않는다.
#include "prompt_airlock/vault_client/types.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <utility>

namespace pv = prompt_airlock::vault_client;

namespace {

pv::AuthSecret make(char digit) {
    auto s = pv::AuthSecret::from_hex(std::string(2 * pv::AuthSecret::size, digit));
    EXPECT_TRUE(s);
    return std::move(*s);
}

bool all_equal(const pv::AuthSecret& s, std::uint8_t v) {
    return std::ranges::all_of(s.bytes(), [v](std::uint8_t b) { return b == v; });
}

}  // namespace

TEST(VaultClientTypes, MoveAssignWipesSource) {
    auto a = make('1');
    auto b = make('2');
    b = std::move(a);
    EXPECT_TRUE(all_equal(b, 0x11));
    EXPECT_TRUE(all_equal(a, 0x00));
}

TEST(VaultClientTypes, SelfMoveKeepsSecret) {
    auto a = make('3');
    auto& alias = a;
    a = std::move(alias);
    EXPECT_TRUE(all_equal(a, 0x33));
}
