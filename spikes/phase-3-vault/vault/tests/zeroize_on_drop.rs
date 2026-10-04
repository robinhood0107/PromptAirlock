//! zeroize 검증: 전역 할당자가 해제 직전의 모든 heap 블록에서 표식(SENTINEL 연속 32바이트)을 찾는다.
//!
//! 이 시험이 보여 주는 것: Vault 코드 경로가 heap 에 만든 원문 사본은 해제 전에 지워진다.
//! 보여 주지 못하는 것: 커널 소켓/파이프 버퍼, 스택, 레지스터, 스왑, 크래시 덤프, 해제되지 않은 채 남은 사본,
//! realloc 이전 위치 등. 즉 "다른 사본이 없다"는 증명이 아니다(spec §31).
#![allow(unsafe_code)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use prompt_airlock_vault::actor;
use prompt_airlock_vault::clock::{ManualClock, SystemClock};
use prompt_airlock_vault::config::{ActorConfig, ServerConfig, VaultLimits};
use prompt_airlock_vault::proto::{self, request::Op, response::Result as R};
use prompt_airlock_vault::server::{ServerContext, serve_connection};
use prompt_airlock_vault::state::VaultState;
use prompt_airlock_vault::types::{AuthSecret, EntityLabel, SecretValue};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroize;

const SENTINEL: u8 = 0xC3;
/// 음성 대조군 표식. 해제된 대조군 메모리가 재사용돼 SENTINEL 탐지를 오염시키지 않게 값을 다르게 둔다.
const NEG_SENTINEL: u8 = 0x3C;
const RUN: usize = 32;
/// 원문 값 크기. 정확히 이 크기로 해제된 블록이 0 인지도 따로 센다(양성 증거).
const MARK: usize = 3001;

static ARMED: AtomicBool = AtomicBool::new(false);
static DIRTY: AtomicUsize = AtomicUsize::new(0);
static NEG_DIRTY: AtomicUsize = AtomicUsize::new(0);
static MARK_ZEROED: AtomicUsize = AtomicUsize::new(0);
static DIRTY_SIZES: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];

fn has_sentinel_run(bytes: &[u8], pat: u8) -> bool {
    let mut run = 0usize;
    for b in bytes {
        if *b == pat {
            run += 1;
            if run >= RUN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

struct Probe;

// SAFETY: 할당은 System 에 그대로 위임한다. dealloc 에서는 해제 전(아직 유효한) 블록을 읽기만 한다.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // 재사용된 블록의 이전 내용 때문에 오탐하지 않도록 할당 시 0 으로 채운다.
        // 그러면 해제 시 발견된 표식은 반드시 그 블록의 수명 동안 쓰인 것이다.
        // SAFETY: GlobalAlloc 계약 그대로 전달. alloc_zeroed 는 layout 크기만큼 0 으로 채운 블록을 준다.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size();
        if ARMED.load(Ordering::Relaxed) && size >= RUN {
            // SAFETY: ptr 은 이 할당자가 layout 으로 할당했고 아직 해제하지 않은 블록이다.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, size) };
            if has_sentinel_run(bytes, NEG_SENTINEL) {
                NEG_DIRTY.fetch_add(1, Ordering::SeqCst);
            }
            if has_sentinel_run(bytes, SENTINEL) {
                let n = DIRTY.fetch_add(1, Ordering::SeqCst);
                if n < DIRTY_SIZES.len() {
                    DIRTY_SIZES[n].store(size, Ordering::SeqCst);
                }
            } else if size == MARK && bytes.iter().all(|b| *b == 0) {
                MARK_ZEROED.fetch_add(1, Ordering::SeqCst);
            }
        }
        // SAFETY: GlobalAlloc 계약 그대로 전달.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Probe = Probe;

fn reset() {
    DIRTY.store(0, Ordering::SeqCst);
    MARK_ZEROED.store(0, Ordering::SeqCst);
    for s in &DIRTY_SIZES {
        s.store(0, Ordering::SeqCst);
    }
}

fn dirty_sizes() -> Vec<usize> {
    let n = DIRTY.load(Ordering::SeqCst).min(DIRTY_SIZES.len());
    DIRTY_SIZES[..n].iter().map(|s| s.load(Ordering::SeqCst)).collect()
}

fn value() -> SecretValue {
    SecretValue::from_vec(vec![SENTINEL; MARK])
}

fn l(s: &str) -> EntityLabel {
    EntityLabel::parse(s).unwrap()
}

/// 서버 연결 하나로 hello → scope → token → resolve → drop 을 수행한다. 시험 클라이언트 사본도 지운다.
async fn ipc_flow<S: AsyncRead + AsyncWrite + Unpin>(c: &mut S, secret: &[u8]) {
    common::call(c, 1, common::hello(secret)).await;
    let Some(R::CreateScope(cs)) = common::call(c, 2, common::create_scope(60_000)).await.result else { panic!() };
    let op = Op::CreateToken(proto::CreateTokenRequest {
        scope_id: cs.scope_id.clone(),
        entity_type: "PERSON".into(),
        value: vec![SENTINEL; MARK],
    });
    let Some(R::CreateToken(tok)) = common::call(c, 3, op).await.result else { panic!() };
    let op = Op::ResolveExact(proto::ResolveExactRequest { scope_id: cs.scope_id.clone(), token: tok.token });
    let Some(R::ResolveExact(mut v)) = common::call(c, 4, op).await.result else { panic!() };
    assert_eq!(v.value.len(), MARK);
    v.value.zeroize();
    common::call(c, 5, Op::DropScope(proto::DropScopeRequest { scope_id: cs.scope_id })).await;
}

#[test]
fn vault_buffers_are_zeroed_before_free() {
    ARMED.store(true, Ordering::SeqCst);

    // 0) 음성 대조: 일반 Vec 는 표식이 남은 채 해제된다 → 탐지 장치 동작 확인
    drop(std::hint::black_box(vec![NEG_SENTINEL; 4096]));
    assert!(NEG_DIRTY.load(Ordering::SeqCst) >= 1, "probe 가 표식을 탐지하지 못함");
    reset();

    // 1) 상태 직접 조작: 저장, 중복 저장(새 사본 폐기), 복원 사본, DropScope
    let clock = ManualClock::new();
    let mut st = VaultState::new(VaultLimits::default(), clock.clone());
    let (s, _) = st.create_scope(Duration::from_secs(60)).unwrap();
    let t = st.create_token(&s, l("PERSON"), value()).unwrap();
    assert_eq!(t, st.create_token(&s, l("PERSON"), value()).unwrap());
    let (_, copy) = st.resolve_exact(&s, t.as_str()).unwrap();
    drop(copy);
    st.drop_scope(&s).unwrap();
    // 2) TTL 만료(지연 제거와 sweep)
    let (s1, _) = st.create_scope(Duration::from_secs(1)).unwrap();
    let (s2, _) = st.create_scope(Duration::from_secs(1)).unwrap();
    let t1 = st.create_token(&s1, l("PERSON"), value()).unwrap();
    st.create_token(&s2, l("PERSON"), value()).unwrap();
    clock.advance(Duration::from_secs(2));
    assert!(st.resolve_exact(&s1, t1.as_str()).is_err());
    assert_eq!(st.sweep(), 1);
    // 3) 남은 상태 전체 drop
    let (s3, _) = st.create_scope(Duration::from_secs(60)).unwrap();
    st.create_token(&s3, l("PERSON"), value()).unwrap();
    drop(st);
    // 4) actor 종료 경로
    let (h, j) = actor::spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
    let (s4, _) = h.create_scope(Duration::from_secs(60)).unwrap().wait_blocking().unwrap();
    h.create_token(s4, l("PERSON"), value()).unwrap().wait_blocking().unwrap();
    j.shutdown();

    let zeroed = MARK_ZEROED.load(Ordering::SeqCst);
    eprintln!("state path: zeroed_mark_buffers={zeroed} dirty={:?}", dirty_sizes());
    assert!(dirty_sizes().is_empty(), "Vault 상태 경로에서 원문이 남은 채 해제됨: {:?}", dirty_sizes());
    // 저장 5 + 중복 사본 1 + 복원 사본 1
    assert!(zeroed >= 7, "zeroed={zeroed}");
    reset();

    // 5) IPC 서버 경로(in-memory duplex, 관찰). duplex 내부 BytesMut 는 커널 버퍼에 해당하며 지워지지 않는다.
    const DUPLEX_CAP: usize = 1 << 16;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (h, j) = actor::spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
        let secret = [9u8; 32];
        let ctx = ServerContext::new(h, AuthSecret::from_bytes(secret), ServerConfig::default());
        let (mut c, srv) = tokio::io::duplex(DUPLEX_CAP);
        let task = tokio::spawn(serve_connection(srv, ctx));
        ipc_flow(&mut c, &secret).await;
        drop(c);
        let _ = task.await;
        j.shutdown();
    });
    drop(rt);
    let sizes = dirty_sizes();
    eprintln!("duplex IPC path: zeroed_mark_buffers={} dirty_sizes={sizes:?}", MARK_ZEROED.load(Ordering::SeqCst));
    reset();

    // 6) Windows named pipe 실제 경로: tokio/mio 의 사용자 공간 I/O 버퍼를 측정한다(판정이 아니라 관찰).
    #[cfg(windows)]
    {
        use prompt_airlock_vault::transport::pipe::{PipeAcl, run};
        use tokio::net::windows::named_pipe::ClientOptions;
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(async {
            let (h, j) = actor::spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
            let secret = [5u8; 32];
            let ctx = ServerContext::new(h, AuthSecret::from_bytes(secret), ServerConfig::default());
            let mut b = [0u8; 8];
            prompt_airlock_vault::types::csprng_fill(&mut b).unwrap();
            let name = format!(r"\\.\pipe\pa-vault-zeroize-{:016x}", u64::from_le_bytes(b));
            let (tx, rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(run(ctx, name, PipeAcl::CurrentUser, move |ep| {
                let _ = tx.send(ep);
            }));
            let ep = rx.await.unwrap();
            let mut c = ClientOptions::new().open(&ep).unwrap();
            ipc_flow(&mut c, &secret).await;
            drop(c);
            server.abort();
            let _ = server.await;
            j.shutdown();
        });
        drop(rt);
        eprintln!(
            "named pipe IPC path (observation): zeroed_mark_buffers={} dirty_sizes={:?}",
            MARK_ZEROED.load(Ordering::SeqCst),
            dirty_sizes()
        );
    }
    // 6u) Linux UDS 실제 경로(판정). tokio UnixStream 도 사용자 공간 버퍼 없이 직접 send/recv 한다.
    #[cfg(unix)]
    {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        reset();
        rt.block_on(async {
            let (h, j) = actor::spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
            let secret = [7u8; 32];
            let ctx = ServerContext::new(h, AuthSecret::from_bytes(secret), ServerConfig::default());
            let mut b = [0u8; 8];
            prompt_airlock_vault::types::csprng_fill(&mut b).unwrap();
            let dir = std::env::temp_dir().join(format!("pa-vault-zeroize-{:016x}", u64::from_le_bytes(b)));
            let path = dir.join("vault.sock");
            let (tx, rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(prompt_airlock_vault::transport::uds::run(ctx, path.clone(), move |ep| {
                let _ = tx.send(ep);
            }));
            rx.await.unwrap();
            let mut c = tokio::net::UnixStream::connect(&path).await.unwrap();
            ipc_flow(&mut c, &secret).await;
            drop(c);
            server.abort();
            let _ = server.await;
            let _ = std::fs::remove_dir(&dir);
            j.shutdown();
        });
        drop(rt);
        eprintln!("uds IPC path: zeroed_mark_buffers={} dirty_sizes={:?}", MARK_ZEROED.load(Ordering::SeqCst), dirty_sizes());
        assert!(dirty_sizes().is_empty(), "UDS IPC 경로에서 원문이 남은 채 해제됨: {:?}", dirty_sizes());
    }
    // 6') TCP loopback 실제 경로(판정). mio TcpStream 은 사용자 공간 버퍼 없이 우리 버퍼로 직접 send/recv 한다.
    {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        reset();
        rt.block_on(async {
            let (h, j) = actor::spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
            let secret = [6u8; 32];
            let ctx = ServerContext::new(h, AuthSecret::from_bytes(secret), ServerConfig::default());
            let (tx, rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(prompt_airlock_vault::transport::run_tcp(ctx, move |ep| {
                let _ = tx.send(ep);
            }));
            let ep = rx.await.unwrap();
            let mut c = tokio::net::TcpStream::connect(ep).await.unwrap();
            ipc_flow(&mut c, &secret).await;
            drop(c);
            server.abort();
            let _ = server.await;
            j.shutdown();
        });
        drop(rt);
        eprintln!(
            "tcp IPC path: zeroed_mark_buffers={} dirty_sizes={:?}",
            MARK_ZEROED.load(Ordering::SeqCst),
            dirty_sizes()
        );
        assert!(dirty_sizes().is_empty(), "TCP IPC 경로에서 원문이 남은 채 해제됨: {:?}", dirty_sizes());
    }
    ARMED.store(false, Ordering::SeqCst);
}
