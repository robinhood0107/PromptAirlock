//! prompt-airlock-vault 실행 파일.
//!
//! 시작 순서: actor 시작 → transport bind → stdout 에 READY 한 줄(엔드포인트·pid·실행별 비밀값) 출력.
//! 비밀값은 부모 프로세스만 읽는 stdout 파이프로만 나간다(명령줄 인자 사용 안 함).
//! stdin 이 EOF 가 되면(부모 종료) 스스로 종료하고 모든 mapping 을 drop(zeroize)한다.
//! stderr 에는 원문·token·scope id·비밀값을 쓰지 않는다.
//! 해제하는 모든 메모리는 0으로 지운다(alloc::WipingAllocator, ADR 0019). TCP 는 열지 않는다(ADR 0003).

use std::io::{Read, Write};
use std::process::ExitCode;
use std::time::Duration;

use prompt_airlock_vault::actor;
use prompt_airlock_vault::alloc::WipingAllocator;
use prompt_airlock_vault::clock::SystemClock;
use prompt_airlock_vault::config::{ActorConfig, ServerConfig, VaultLimits};
use prompt_airlock_vault::server::ServerContext;
use prompt_airlock_vault::transport;
use prompt_airlock_vault::types::{AuthSecret, csprng_fill};

#[global_allocator]
static ALLOC: WipingAllocator = WipingAllocator(std::alloc::System);

// 운영체제마다 하나뿐인 로컬 transport(ADR 0003).
#[cfg(windows)]
const TRANSPORT: &str = "pipe";
#[cfg(unix)]
const TRANSPORT: &str = "uds";

struct Args {
    endpoint: Option<String>,
    limits: VaultLimits,
    actor: ActorConfig,
    server: ServerConfig,
    watch_stdin: bool,
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: prompt-airlock-vault [--transport {TRANSPORT}] [--endpoint <name|path>]\n\
         \x20 [--max-scopes N] [--max-mappings N] [--max-value-bytes N] [--max-ttl-ms N] [--queue N]\n\
         \x20 [--max-frame N] [--max-connections N] [--no-stdin-watch]"
    );
    ExitCode::from(2)
}

fn parse_args() -> Option<Args> {
    let mut a = Args {
        endpoint: None,
        limits: VaultLimits::default(),
        actor: ActorConfig::default(),
        server: ServerConfig::default(),
        watch_stdin: true,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut num = || it.next().and_then(|v| v.parse::<usize>().ok());
        match flag.as_str() {
            // 다른 transport 이름(tcp 등)은 받지 않는다.
            "--transport" => {
                if it.next()? != TRANSPORT {
                    return None;
                }
            }
            "--endpoint" => a.endpoint = Some(it.next()?),
            "--max-scopes" => a.limits.max_scopes = num()?,
            "--max-mappings" => a.limits.max_mappings_per_scope = num()?,
            "--max-value-bytes" => a.limits.max_value_bytes = num()?,
            "--max-ttl-ms" => a.limits.max_ttl = Duration::from_millis(num()? as u64),
            "--queue" => a.actor.queue_capacity = num()?,
            "--max-frame" => a.server.max_frame_bytes = num()?,
            "--max-connections" => a.server.max_connections = num()?,
            "--no-stdin-watch" => a.watch_stdin = false,
            _ => return None,
        }
    }
    Some(a)
}

fn random_hex(n: usize) -> Option<String> {
    let mut b = vec![0u8; n];
    csprng_fill(&mut b).ok()?;
    Some(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn default_endpoint() -> Option<String> {
    let suffix = random_hex(16)?;
    #[cfg(windows)]
    {
        Some(format!(r"\\.\pipe\prompt-airlock-vault-{suffix}"))
    }
    #[cfg(unix)]
    {
        let base =
            std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
        Some(base.join(format!("prompt-airlock-vault-{suffix}")).join("vault.sock").display().to_string())
    }
}

fn main() -> ExitCode {
    let Some(args) = parse_args() else { return usage() };
    let Ok(secret) = AuthSecret::generate() else {
        eprintln!("vault: CSPRNG unavailable");
        return ExitCode::from(3);
    };
    let secret_hex = secret.to_hex();
    let Some(endpoint) = args.endpoint.clone().or_else(default_endpoint) else {
        return ExitCode::from(3);
    };
    let (handle, actor_join) = match actor::spawn(args.limits.clone(), args.actor.clone(), SystemClock::new()) {
        Ok(x) => x,
        Err(_) => return ExitCode::from(3),
    };
    let ctx = ServerContext::new(handle, secret, args.server.clone());

    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(_) => return ExitCode::from(3),
    };

    let ready = move |ep: String| {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(
            out,
            "PA-VAULT-READY v=1 transport={TRANSPORT} endpoint={ep} pid={} secret={}",
            std::process::id(),
            &*secret_hex
        );
        let _ = out.flush();
    };

    // 부모가 사라지면 stdin 이 EOF 가 된다. 별도 OS 스레드로 감시해 런타임 종료를 막지 않는다.
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    if args.watch_stdin {
        std::thread::spawn(move || {
            let mut sink = [0u8; 64];
            let mut stdin = std::io::stdin();
            while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
            let _ = stop_tx.send(());
        });
    } else {
        std::mem::forget(stop_tx);
    }

    let result = rt.block_on(async move {
        #[cfg(windows)]
        let serve = transport::pipe::run(ctx, endpoint, ready);
        #[cfg(unix)]
        let serve = transport::uds::run(ctx, endpoint.into(), ready);
        tokio::select! {
            r = serve => r,
            _ = stop_rx => Ok(()),
        }
    });
    rt.shutdown_timeout(Duration::from_secs(1));
    actor_join.shutdown();
    match result {
        Ok(()) => {
            eprintln!("vault: stopped");
            ExitCode::SUCCESS
        }
        Err(e) => {
            // io 오류 종류만 남긴다(경로·이름 미포함).
            eprintln!("vault: transport error kind={:?}", e.kind());
            ExitCode::from(4)
        }
    }
}
