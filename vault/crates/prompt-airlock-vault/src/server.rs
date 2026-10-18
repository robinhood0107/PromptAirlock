//! 연결 처리. transport 와 무관하게 AsyncRead + AsyncWrite 스트림 하나를 받는다.
//!
//! 규칙
//! - 첫 frame 은 hello(실행별 비밀값)여야 한다. 실패하면 오류 응답 후 연결 종료.
//! - frame 크기 초과, 디코딩 실패, 버전 불일치는 오류 응답 후 연결 종료(재동기화 시도 안 함).
//! - 요청 처리 중 오류는 코드만 보낸다. 로그에 원문·token·scope id 를 남기지 않는다.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use zeroize::Zeroize;

use crate::actor::VaultHandle;
use crate::codec::{self, FrameError};
use crate::config::ServerConfig;
use crate::error::VaultError;
use crate::proto::{self, ErrorCode, ProtocolVersion, request::Op, response::Result as R};
use crate::types::{AuthSecret, EntityLabel, ScopeId, SecretValue};

pub struct ServerContext {
    pub vault: VaultHandle,
    pub secret: AuthSecret,
    pub cfg: ServerConfig,
    pub conn_limit: Arc<Semaphore>,
}

impl ServerContext {
    pub fn new(vault: VaultHandle, secret: AuthSecret, cfg: ServerConfig) -> Arc<Self> {
        let conn_limit = Arc::new(Semaphore::new(cfg.max_connections));
        Arc::new(Self { vault, secret, cfg, conn_limit })
    }
}

fn response(request_id: u64, result: R) -> proto::Response {
    proto::Response { protocol_version: ProtocolVersion::V1 as i32, request_id, result: Some(result) }
}

fn error(request_id: u64, code: ErrorCode) -> proto::Response {
    response(request_id, R::Error(proto::Error { code: code as i32 }))
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, mut resp: proto::Response, t: Duration) -> Result<(), FrameError> {
    let frame = codec::encode_response(&mut resp);
    codec::write_frame(s, &frame, t).await
}

/// 연결 하나를 끝까지 처리한다. 연결 수 한도를 넘으면 OVERLOADED 후 종료한다.
pub async fn serve_connection<S>(mut stream: S, ctx: Arc<ServerContext>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(_permit) = ctx.conn_limit.clone().try_acquire_owned() else {
        let _ = send(&mut stream, error(0, ErrorCode::Overloaded), ctx.cfg.write_timeout).await;
        return;
    };
    let cfg = &ctx.cfg;
    let mut authed = false;
    loop {
        let header_timeout = if authed { cfg.idle_timeout } else { cfg.hello_timeout };
        let frame = match codec::read_frame(&mut stream, cfg.max_frame_bytes, header_timeout, cfg.frame_body_timeout).await
        {
            Ok(f) => f,
            Err(FrameError::TooLarge) => {
                let _ = send(&mut stream, error(0, ErrorCode::FrameTooLarge), cfg.write_timeout).await;
                return;
            }
            Err(_) => return,
        };
        let Ok(mut req) = codec::decode_wiping::<proto::Request>(frame) else {
            let _ = send(&mut stream, error(0, ErrorCode::MalformedRequest), cfg.write_timeout).await;
            return;
        };
        if req.protocol_version != ProtocolVersion::V1 as i32 {
            codec::scrub_request(&mut req);
            let _ = send(&mut stream, error(req.request_id, ErrorCode::UnsupportedVersion), cfg.write_timeout).await;
            return;
        }
        let id = req.request_id;
        let (resp, close) = dispatch(&ctx, &mut authed, req).await;
        let resp = match resp {
            Ok(r) => response(id, r),
            Err(code) => error(id, code),
        };
        if send(&mut stream, resp, cfg.write_timeout).await.is_err() || close {
            return;
        }
    }
}

/// (응답, 연결 종료 여부)
async fn dispatch(ctx: &ServerContext, authed: &mut bool, req: proto::Request) -> (Result<R, ErrorCode>, bool) {
    let Some(op) = req.op else {
        return (Err(ErrorCode::MalformedRequest), true);
    };
    match op {
        Op::Hello(mut h) => {
            let ok = !*authed && ctx.secret.ct_eq(&h.auth_secret);
            h.auth_secret.zeroize();
            if ok {
                *authed = true;
                (Ok(R::Hello(proto::HelloAck {})), false)
            } else {
                (Err(ErrorCode::AuthFailed), true)
            }
        }
        mut other if !*authed => {
            if let Op::CreateToken(r) = &mut other {
                r.value.zeroize();
            }
            (Err(ErrorCode::AuthRequired), true)
        }
        other => (handle_op(ctx, other).await.map_err(VaultError::to_proto), false),
    }
}

async fn handle_op(ctx: &ServerContext, op: Op) -> Result<R, VaultError> {
    let v = &ctx.vault;
    match op {
        Op::CreateScope(r) => {
            let (scope, ttl) = v.create_scope(Duration::from_millis(r.ttl_ms))?.wait().await?;
            Ok(R::CreateScope(proto::CreateScopeResponse {
                scope_id: scope.as_bytes().to_vec(),
                ttl_ms: u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX),
            }))
        }
        Op::CreateToken(mut r) => {
            // 원문을 먼저 SecretValue 로 옮긴다. 이후 어떤 경로로 끝나도 drop 시 zeroize 된다.
            let value = SecretValue::from_vec(std::mem::take(&mut r.value));
            let scope = ScopeId::from_slice(&r.scope_id)?;
            let label = EntityLabel::parse(&r.entity_type)?;
            let tok = v.create_token(scope, label, value)?.wait().await?;
            Ok(R::CreateToken(proto::CreateTokenResponse { token: tok.as_str().to_owned() }))
        }
        Op::ResolveExact(r) => {
            let scope = ScopeId::from_slice(&r.scope_id)?;
            let (label, mut value) = v.resolve_exact(scope, r.token)?.wait().await?;
            // Zeroizing 안의 Vec 를 꺼내 응답에 넣는다. 응답 인코딩 직후 scrub_response 가 지운다.
            Ok(R::ResolveExact(proto::ResolveExactResponse {
                entity_type: label.as_str().to_owned(),
                value: std::mem::take(&mut *value),
            }))
        }
        Op::DropScope(r) => {
            let scope = ScopeId::from_slice(&r.scope_id)?;
            v.drop_scope(scope)?.wait().await?;
            Ok(R::DropScope(proto::DropScopeResponse {}))
        }
        Op::Hello(_) => Err(VaultError::InvalidArgument),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor;
    use crate::clock::SystemClock;
    use crate::config::{ActorConfig, VaultLimits};
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    const SECRET: [u8; 32] = [42u8; 32];

    fn ctx() -> (Arc<ServerContext>, actor::ActorJoin) {
        let (h, j) = actor::spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
        (ServerContext::new(h, AuthSecret::from_bytes(SECRET), ServerConfig::default()), j)
    }

    fn start(ctx: Arc<ServerContext>) -> DuplexStream {
        let (client, server) = tokio::io::duplex(1 << 20);
        tokio::spawn(serve_connection(server, ctx));
        client
    }

    async fn read_resp(c: &mut DuplexStream) -> Option<proto::Response> {
        let mut hdr = [0u8; 4];
        c.read_exact(&mut hdr).await.ok()?;
        let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
        c.read_exact(&mut body).await.ok()?;
        Some(proto::Response::decode(&body[..]).unwrap())
    }

    async fn call(c: &mut DuplexStream, id: u64, op: Op) -> proto::Response {
        let mut req = proto::Request { protocol_version: ProtocolVersion::V1 as i32, request_id: id, op: Some(op) };
        c.write_all(&codec::encode_request(&mut req)).await.unwrap();
        let r = read_resp(c).await.unwrap();
        assert_eq!(r.request_id, id);
        r
    }

    fn err_code(r: &proto::Response) -> Option<ErrorCode> {
        match &r.result {
            Some(R::Error(e)) => ErrorCode::try_from(e.code).ok(),
            _ => None,
        }
    }

    async fn is_closed(c: &mut DuplexStream) -> bool {
        let mut b = [0u8; 1];
        matches!(c.read(&mut b).await, Ok(0) | Err(_))
    }

    fn hello(secret: &[u8]) -> Op {
        Op::Hello(proto::Hello { auth_secret: secret.to_vec() })
    }

    #[tokio::test]
    async fn full_flow() {
        let (ctx, _j) = ctx();
        let mut c = start(ctx);
        assert!(matches!(call(&mut c, 1, hello(&SECRET)).await.result, Some(R::Hello(_))));
        let r = call(&mut c, 2, Op::CreateScope(proto::CreateScopeRequest { ttl_ms: 60_000 })).await;
        let Some(R::CreateScope(cs)) = r.result else { panic!() };
        let mk = |v: &str| {
            Op::CreateToken(proto::CreateTokenRequest {
                scope_id: cs.scope_id.clone(),
                entity_type: "PERSON".into(),
                value: v.as_bytes().to_vec(),
            })
        };
        let Some(R::CreateToken(t1)) = call(&mut c, 3, mk("합성인물A")).await.result else { panic!() };
        let Some(R::CreateToken(t2)) = call(&mut c, 4, mk("합성인물A")).await.result else { panic!() };
        assert_eq!(t1.token, t2.token);
        let r = call(&mut c, 5, Op::ResolveExact(proto::ResolveExactRequest { scope_id: cs.scope_id.clone(), token: t1.token.clone() })).await;
        let Some(R::ResolveExact(v)) = r.result else { panic!() };
        assert_eq!(v.value, "합성인물A".as_bytes());
        let r = call(&mut c, 6, Op::ResolveExact(proto::ResolveExactRequest { scope_id: vec![1; 16], token: t1.token.clone() })).await;
        assert_eq!(err_code(&r), Some(ErrorCode::ScopeNotFound));
        let r = call(&mut c, 7, Op::DropScope(proto::DropScopeRequest { scope_id: cs.scope_id.clone() })).await;
        assert!(matches!(r.result, Some(R::DropScope(_))));
        let r = call(&mut c, 8, Op::ResolveExact(proto::ResolveExactRequest { scope_id: cs.scope_id.clone(), token: t1.token })).await;
        assert_eq!(err_code(&r), Some(ErrorCode::ScopeNotFound));
        // 잘못된 scope id 길이는 INVALID_ARGUMENT 이며 연결은 유지된다
        let r = call(&mut c, 9, Op::DropScope(proto::DropScopeRequest { scope_id: vec![1; 3] })).await;
        assert_eq!(err_code(&r), Some(ErrorCode::InvalidArgument));
        let r = call(&mut c, 10, Op::CreateScope(proto::CreateScopeRequest { ttl_ms: 1000 })).await;
        assert!(matches!(r.result, Some(R::CreateScope(_))));
    }

    #[tokio::test]
    async fn wrong_secret_closes() {
        let (ctx, _j) = ctx();
        let mut c = start(ctx);
        let r = call(&mut c, 1, hello(&[0u8; 32])).await;
        assert_eq!(err_code(&r), Some(ErrorCode::AuthFailed));
        assert!(is_closed(&mut c).await);
    }

    #[tokio::test]
    async fn op_before_hello_is_rejected() {
        let (ctx, _j) = ctx();
        let mut c = start(ctx);
        let r = call(&mut c, 1, Op::CreateScope(proto::CreateScopeRequest { ttl_ms: 1000 })).await;
        assert_eq!(err_code(&r), Some(ErrorCode::AuthRequired));
        assert!(is_closed(&mut c).await);
    }

    #[tokio::test]
    async fn second_hello_is_rejected() {
        let (ctx, _j) = ctx();
        let mut c = start(ctx);
        call(&mut c, 1, hello(&SECRET)).await;
        let r = call(&mut c, 2, hello(&SECRET)).await;
        assert_eq!(err_code(&r), Some(ErrorCode::AuthFailed));
    }

    #[tokio::test]
    async fn bad_version_garbage_and_oversize() {
        let (ctx, _j) = ctx();
        // 버전 불일치
        let mut c = start(ctx.clone());
        let mut req = proto::Request { protocol_version: 2, request_id: 7, op: Some(hello(&SECRET)) };
        c.write_all(&codec::encode_request(&mut req)).await.unwrap();
        let r = read_resp(&mut c).await.unwrap();
        assert_eq!(err_code(&r), Some(ErrorCode::UnsupportedVersion));
        assert!(is_closed(&mut c).await);
        // 쓰레기 바이트
        let mut c = start(ctx.clone());
        c.write_all(&[0, 0, 0, 5, 0xff, 0xff, 0xff, 0xff, 0xff]).await.unwrap();
        let r = read_resp(&mut c).await.unwrap();
        assert_eq!(err_code(&r), Some(ErrorCode::MalformedRequest));
        assert!(is_closed(&mut c).await);
        // 큰 frame
        let mut c = start(ctx.clone());
        c.write_all(&(10_000_000u32).to_be_bytes()).await.unwrap();
        let r = read_resp(&mut c).await.unwrap();
        assert_eq!(err_code(&r), Some(ErrorCode::FrameTooLarge));
        assert!(is_closed(&mut c).await);
        // 이후에도 서버는 정상
        let mut c = start(ctx);
        assert!(matches!(call(&mut c, 1, hello(&SECRET)).await.result, Some(R::Hello(_))));
    }

    #[tokio::test]
    async fn hello_timeout_closes_idle_connection() {
        let (h, _j) = actor::spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
        let cfg = ServerConfig { hello_timeout: Duration::from_millis(50), ..ServerConfig::default() };
        let ctx = ServerContext::new(h, AuthSecret::from_bytes(SECRET), cfg);
        let mut c = start(ctx);
        assert!(is_closed(&mut c).await);
    }

    #[tokio::test]
    async fn connection_limit_is_overloaded() {
        let (h, _j) = actor::spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
        let cfg = ServerConfig { max_connections: 1, ..ServerConfig::default() };
        let ctx = ServerContext::new(h, AuthSecret::from_bytes(SECRET), cfg);
        let mut c1 = start(ctx.clone());
        call(&mut c1, 1, hello(&SECRET)).await;
        let mut c2 = start(ctx);
        let r = read_resp(&mut c2).await.unwrap();
        assert_eq!(err_code(&r), Some(ErrorCode::Overloaded));
    }
}
