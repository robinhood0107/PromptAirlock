//! 지우는 할당기(ADR 0019) 판정: 전역 할당기를 WipingAllocator<Probe> 로 두고, Probe 가 해제 직전 블록에서
//! 표식(SENTINEL 연속 32바이트)을 찾는다. 해제·재할당·실제 IPC 경로(Windows Named Pipe, Linux UDS) 모두에서
//! 표식이 남은 채 해제된 블록이 없어야 한다. 시험 전용 할당기라 unsafe 를 허용한다.
#![allow(unsafe_code)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use prompt_airlock_vault::actor;
use prompt_airlock_vault::alloc::WipingAllocator;
use prompt_airlock_vault::clock::SystemClock;
use prompt_airlock_vault::config::{ActorConfig, ServerConfig, VaultLimits};
use prompt_airlock_vault::proto::{self, request::Op, response::Result as R};
use prompt_airlock_vault::server::ServerContext;
use prompt_airlock_vault::types::AuthSecret;
use tokio::io::{AsyncRead, AsyncWrite};

const SENTINEL: u8 = 0xC3;
const RUN: usize = 32;
const MARK: usize = 3001;

static ARMED: AtomicBool = AtomicBool::new(false);
static DIRTY: AtomicUsize = AtomicUsize::new(0);
static MARK_FREED: AtomicUsize = AtomicUsize::new(0);

fn has_sentinel_run(bytes: &[u8]) -> bool {
    let mut run = 0usize;
    for b in bytes {
        run = if *b == SENTINEL { run + 1 } else { 0 };
        if run >= RUN {
            return true;
        }
    }
    false
}

struct Probe;

// SAFETY: System 에 위임한다. dealloc 에서는 아직 유효한 블록을 읽기만 한다.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // 재사용 블록의 이전 내용으로 오탐하지 않도록 0으로 채워 준다.
        // SAFETY: 계약 그대로 위임한다.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) && layout.size() >= RUN {
            // SAFETY: ptr 은 layout 크기의 아직 유효한 블록이다.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if has_sentinel_run(bytes) {
                DIRTY.fetch_add(1, Ordering::SeqCst);
            }
            if layout.size() == MARK {
                MARK_FREED.fetch_add(1, Ordering::SeqCst);
            }
        }
        // SAFETY: 계약 그대로 위임한다.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: WipingAllocator<Probe> = WipingAllocator(Probe);

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
    let Some(R::ResolveExact(v)) = common::call(c, 4, op).await.result else { panic!() };
    assert_eq!(v.value.len(), MARK);
    common::call(c, 5, Op::DropScope(proto::DropScopeRequest { scope_id: cs.scope_id })).await;
}

#[test]
fn freed_memory_is_wiped() {
    // 탐지기 자체 확인: 표식이 있는 슬라이스를 직접 보면 찾는다.
    assert!(has_sentinel_run(&[SENTINEL; MARK]));

    ARMED.store(true, Ordering::SeqCst);

    // 1) 일반 해제: 지우는 할당기가 없으면 표식이 남는 경로다.
    drop(std::hint::black_box(vec![SENTINEL; MARK]));
    assert!(MARK_FREED.load(Ordering::SeqCst) >= 1, "표식 블록 해제를 보지 못함");
    assert_eq!(DIRTY.load(Ordering::SeqCst), 0, "해제한 블록에 원문이 남음");

    // 2) 재할당: 옛 영역도 지워져야 한다.
    let mut grow = Vec::with_capacity(MARK);
    grow.extend(std::iter::repeat_n(SENTINEL, MARK));
    grow.reserve(MARK * 4);
    drop(std::hint::black_box(grow));
    assert_eq!(DIRTY.load(Ordering::SeqCst), 0, "재할당으로 버린 영역에 원문이 남음");

    // 3) 실제 IPC 경로(Windows 는 mio 파이프 내부 버퍼를 거친다).
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let (h, j) = actor::spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
        let secret = [5u8; 32];
        let ctx = ServerContext::new(h, AuthSecret::from_bytes(secret), ServerConfig::default());
        let mut b = [0u8; 8];
        prompt_airlock_vault::types::csprng_fill(&mut b).unwrap();
        let tag = u64::from_le_bytes(b);
        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ClientOptions;
            let name = format!(r"\\.\pipe\pa-vault-wipe-{tag:016x}");
            let (tx, rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(prompt_airlock_vault::transport::pipe::run(ctx, name, move |ep| {
                let _ = tx.send(ep);
            }));
            let ep = rx.await.unwrap();
            let mut c = ClientOptions::new().open(&ep).unwrap();
            ipc_flow(&mut c, &secret).await;
            drop(c);
            server.abort();
            let _ = server.await;
        }
        #[cfg(unix)]
        {
            let dir = std::env::temp_dir().join(format!("pa-vault-wipe-{tag:016x}"));
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
        }
        j.shutdown();
    });
    drop(rt);
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(DIRTY.load(Ordering::SeqCst), 0, "IPC 경로에서 원문이 남은 채 해제됨");
}
