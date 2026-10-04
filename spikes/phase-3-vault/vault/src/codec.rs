//! 길이 접두 framing: [u32 big-endian 길이][protobuf]. 최대 frame 크기를 넘으면 본문을 읽지 않는다.

use std::time::Duration;

use bytes::Bytes;
use prost::Message;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

use crate::proto::{self, response};

pub const HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// 연결이 닫혔다(정상 종료 포함).
    Closed,
    Timeout,
    TooLarge,
    Io,
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max_len: usize,
    header_timeout: Duration,
    body_timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let mut hdr = [0u8; HEADER_LEN];
    match timeout(header_timeout, r.read_exact(&mut hdr)).await {
        Err(_) => return Err(FrameError::Timeout),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Ok(Err(_)) => return Err(FrameError::Io),
        Ok(Ok(_)) => {}
    }
    let len = u32::from_be_bytes(hdr) as usize;
    if len > max_len {
        return Err(FrameError::TooLarge);
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    match timeout(body_timeout, r.read_exact(&mut body[..])).await {
        Err(_) => Err(FrameError::Timeout),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(FrameError::Closed),
        Ok(Err(_)) => Err(FrameError::Io),
        Ok(Ok(_)) => Ok(body),
    }
}

/// 메시지를 frame 하나로 인코딩한다. 인코딩 뒤 메시지 안의 원문 필드를 지운다.
pub fn encode_response(resp: &mut proto::Response) -> Zeroizing<Vec<u8>> {
    let len = resp.encoded_len();
    let mut buf = Zeroizing::new(Vec::with_capacity(HEADER_LEN + len));
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    // Vec<u8> 에 대한 encode 는 용량이 충분하면 실패하지 않는다.
    let _ = resp.encode(&mut *buf);
    scrub_response(resp);
    buf
}

pub fn encode_request(req: &mut proto::Request) -> Zeroizing<Vec<u8>> {
    let len = req.encoded_len();
    let mut buf = Zeroizing::new(Vec::with_capacity(HEADER_LEN + len));
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    let _ = req.encode(&mut *buf);
    scrub_request(req);
    buf
}

pub fn scrub_response(resp: &mut proto::Response) {
    if let Some(response::Result::ResolveExact(r)) = resp.result.as_mut() {
        r.value.zeroize();
    }
}

pub fn scrub_request(req: &mut proto::Request) {
    match req.op.as_mut() {
        Some(proto::request::Op::CreateToken(r)) => r.value.zeroize(),
        Some(proto::request::Op::Hello(h)) => h.auth_secret.zeroize(),
        _ => {}
    }
}

/// frame 을 `Bytes` 로 넘겨 decode 한다.
///
/// prost 0.14 의 `bytes` 필드 decode 는 입력이 `&[u8]` 이면 `copy_to_bytes` 로 중간 사본(별도 할당)을 만든 뒤
/// Vec 로 다시 복사하고, 중간 사본은 지우지 않고 해제한다(zeroize 시험에서 탐지). 입력이 `Bytes` 면
/// `copy_to_bytes` 가 같은 버퍼의 slice 라 추가 할당이 없다. decode 뒤 frame 버퍼를 지운다.
pub fn decode_wiping<M: Message + Default>(frame: Zeroizing<Vec<u8>>) -> Result<M, prost::DecodeError> {
    let mut frame = frame;
    let buf = Bytes::from(std::mem::take(&mut *frame));
    let decoded = M::decode(buf.clone());
    wipe(buf);
    decoded
}

/// 유일한 참조면 버퍼를 되찾아 0 으로 지운다. 다른 참조가 남아 있으면 지울 수 없으므로 false.
pub fn wipe(buf: Bytes) -> bool {
    match buf.try_into_mut() {
        Ok(mut m) => {
            m[..].zeroize();
            true
        }
        Err(_) => false,
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &[u8], t: Duration) -> Result<(), FrameError> {
    match timeout(t, async {
        w.write_all(frame).await?;
        w.flush().await
    })
    .await
    {
        Err(_) => Err(FrameError::Timeout),
        Ok(Err(_)) => Err(FrameError::Io),
        Ok(Ok(())) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(1);

    #[tokio::test]
    async fn rejects_oversized_header_without_reading_body() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(1_000_000u32).to_be_bytes()).await.unwrap();
        assert_eq!(read_frame(&mut b, 1024, T, T).await.unwrap_err(), FrameError::TooLarge);
    }

    #[tokio::test]
    async fn truncated_body_is_closed() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(10u32).to_be_bytes()).await.unwrap();
        a.write_all(b"abc").await.unwrap();
        drop(a);
        assert_eq!(read_frame(&mut b, 1024, T, T).await.unwrap_err(), FrameError::Closed);
    }

    #[tokio::test]
    async fn slow_body_times_out() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(10u32).to_be_bytes()).await.unwrap();
        let r = read_frame(&mut b, 1024, T, Duration::from_millis(50)).await;
        assert_eq!(r.unwrap_err(), FrameError::Timeout);
        drop(a);
    }

    #[test]
    fn encode_scrubs_value() {
        let mut resp = proto::Response {
            protocol_version: proto::ProtocolVersion::V1 as i32,
            request_id: 1,
            result: Some(response::Result::ResolveExact(proto::ResolveExactResponse {
                entity_type: "P".into(),
                value: b"synthetic".to_vec(),
            })),
        };
        let frame = encode_response(&mut resp);
        assert!(frame.windows(9).any(|w| w == b"synthetic"));
        match resp.result {
            Some(response::Result::ResolveExact(r)) => assert!(r.value.is_empty()),
            _ => unreachable!(),
        }
    }
}
