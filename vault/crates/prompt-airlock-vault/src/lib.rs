//! Prompt Airlock Secure Mapping Vault.
//!
//! 가명 token 과 원문의 짝을 메모리에만 보관하는 별도 프로세스다(ADR 0002, 0003, 0019). 이 crate 는 provider 자격
//! 증명과 네트워크 외부 접속 경로를 갖지 않는다. 로컬 IPC 서버(Named Pipe 또는 UDS)만 연다.

/// Gateway 와 맞춰야 하는 IPC 프로토콜 버전(proto/vault_v1.proto).
pub const PROTOCOL_VERSION: u32 = 1;
pub const PROTOCOL_PACKAGE: &str = "prompt_airlock.vault.v1";

pub mod proto {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/prompt_airlock.vault.v1.rs"));
}

pub mod actor;
pub mod alloc;
pub mod clock;
pub mod codec;
pub mod config;
pub mod error;
pub mod server;
pub mod state;
pub mod token;
pub mod transport;
pub mod types;
#[cfg(windows)]
pub mod win_sec;

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
