//! 통합 시험용 최소 비동기 클라이언트.
#![allow(dead_code)]

use prompt_airlock_vault::codec;
use prompt_airlock_vault::proto::{self, ProtocolVersion, request::Op};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn call<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, id: u64, op: Op) -> proto::Response {
    let mut req = proto::Request { protocol_version: ProtocolVersion::V1 as i32, request_id: id, op: Some(op) };
    s.write_all(&codec::encode_request(&mut req)).await.unwrap();
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    let mut body = zeroize::Zeroizing::new(vec![0u8; u32::from_be_bytes(hdr) as usize]);
    s.read_exact(&mut body[..]).await.unwrap();
    let r: proto::Response = codec::decode_wiping(body).unwrap();
    assert_eq!(r.request_id, id);
    r
}

pub fn hello(secret: &[u8]) -> Op {
    Op::Hello(proto::Hello { auth_secret: secret.to_vec() })
}

pub fn create_scope(ttl_ms: u64) -> Op {
    Op::CreateScope(proto::CreateScopeRequest { ttl_ms })
}
