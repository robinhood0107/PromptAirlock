// ADR 0019 오류 대응표: Vault·전송 오류가 core 오류로 바뀌는 방식. 실제 Vault 없이 표만 본다.
#include "prompt_airlock/vault_client/service.hpp"

#include <gtest/gtest.h>

namespace pv = prompt_airlock::vault_client;
using pv::ErrorCode;
using prompt_airlock::core::ProtectionError;
using prompt_airlock::core::RestoreError;

TEST(VaultClientMapping, EveryCodeHasACoreError) {
    for (auto i = 0; i <= static_cast<int>(ErrorCode::RestartPending); ++i) {
        const auto c = static_cast<ErrorCode>(i);
        EXPECT_NE(pv::to_string(c), "Unknown");
        // 발급은 원인과 관계없이 발급 불가다.
        EXPECT_EQ(pv::to_protection_error(c), ProtectionError::IssuerUnavailable) << pv::to_string(c);
        // 복원은 token 이 없을 때만 TokenNotFound, 나머지는 복원 불가다.
        const bool not_found = c == ErrorCode::TokenNotFound || c == ErrorCode::MalformedToken;
        EXPECT_EQ(pv::to_restore_error(c), not_found ? RestoreError::TokenNotFound : RestoreError::ResolverUnavailable)
            << pv::to_string(c);
    }
}
