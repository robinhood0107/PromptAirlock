#pragma once

#include <cstdint>
#include <string_view>

namespace prompt_airlock::core {

// 빌드에 박힌 프로젝트 버전.
[[nodiscard]] std::string_view version() noexcept;

// Gateway 와 Vault 가 맞춰야 하는 IPC 프로토콜 버전(proto/vault_v1.proto).
inline constexpr std::uint32_t vault_protocol_version = 1;
inline constexpr std::string_view vault_protocol_package = "prompt_airlock.vault.v1";

}  // namespace prompt_airlock::core
