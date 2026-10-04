#include "prompt_airlock/core/version.hpp"

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>

TEST(CoreVersion, MatchesProjectVersion) {
    EXPECT_EQ(prompt_airlock::core::version(), PA_PROJECT_VERSION);
}

// C++ 쪽 상수와 공용 proto 의 package 가 어긋나면 실패한다.
TEST(CoreVersion, VaultProtocolMatchesProto) {
    std::ifstream in(PA_VAULT_PROTO);
    ASSERT_TRUE(in.is_open());
    std::stringstream buffer;
    buffer << in.rdbuf();
    const std::string proto = buffer.str();
    const std::string package_line =
        "package " + std::string(prompt_airlock::core::vault_protocol_package) + ";";
    EXPECT_NE(proto.find(package_line), std::string::npos);
    EXPECT_NE(proto.find("PROTOCOL_VERSION_V1 = " + std::to_string(prompt_airlock::core::vault_protocol_version) + ";"),
              std::string::npos);
}
