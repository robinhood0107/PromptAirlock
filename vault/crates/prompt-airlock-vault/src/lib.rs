//! Prompt Airlock Secure Mapping Vault.

/// Gateway 와 맞춰야 하는 IPC 프로토콜 버전(proto/vault_v1.proto).
pub const PROTOCOL_VERSION: u32 = 1;
pub const PROTOCOL_PACKAGE: &str = "prompt_airlock.vault.v1";

#[cfg(test)]
mod tests {
    use super::*;

    const PROTO: &str = include_str!("../../../../proto/vault_v1.proto");

    // Rust 쪽 상수와 공용 proto 가 어긋나면 실패한다.
    #[test]
    fn protocol_matches_proto() {
        assert!(PROTO.contains(&format!("package {PROTOCOL_PACKAGE};")));
        assert!(PROTO.contains(&format!("PROTOCOL_VERSION_V1 = {PROTOCOL_VERSION};")));
    }
}
