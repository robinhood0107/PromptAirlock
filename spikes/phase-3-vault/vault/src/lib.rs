//! Prompt Airlock Secure Mapping Vault (Phase 3 spike).
//!
//! 이 crate 는 provider 자격 증명·네트워크 외부 접속 경로를 갖지 않는다. 로컬 IPC 서버만 연다.

pub mod proto {
    #![allow(clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/prompt_airlock.vault.v1.rs"));
}

pub mod actor;
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
