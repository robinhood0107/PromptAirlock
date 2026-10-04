//! transport 별 접근 제어와 왕복 확인.

mod common;



use prompt_airlock_vault::actor;
use prompt_airlock_vault::clock::SystemClock;
use prompt_airlock_vault::config::{ActorConfig, ServerConfig, VaultLimits};
use prompt_airlock_vault::proto::response::Result as R;
use prompt_airlock_vault::server::ServerContext;
use prompt_airlock_vault::transport;
use prompt_airlock_vault::types::AuthSecret;

const SECRET: [u8; 32] = [3u8; 32];

fn ctx() -> (std::sync::Arc<ServerContext>, actor::ActorJoin) {
    let (h, j) = actor::spawn(VaultLimits::default(), ActorConfig::default(), SystemClock::new()).unwrap();
    (ServerContext::new(h, AuthSecret::from_bytes(SECRET), ServerConfig::default()), j)
}

#[tokio::test]
async fn tcp_loopback_roundtrip_and_auth() {
    let (ctx, _j) = ctx();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(transport::run_tcp(ctx, move |ep| {
        let _ = tx.send(ep);
    }));
    let ep = rx.await.unwrap();
    assert!(ep.starts_with("127.0.0.1:"), "{ep}");
    let mut s = tokio::net::TcpStream::connect(&ep).await.unwrap();
    assert!(matches!(common::call(&mut s, 1, common::hello(&SECRET)).await.result, Some(R::Hello(_))));
    assert!(matches!(common::call(&mut s, 2, common::create_scope(1000)).await.result, Some(R::CreateScope(_))));
    let mut bad = tokio::net::TcpStream::connect(&ep).await.unwrap();
    assert!(matches!(common::call(&mut bad, 1, common::hello(&[0u8; 32])).await.result, Some(R::Error(_))));
}

#[cfg(windows)]
mod pipe {
    use super::*;
    use prompt_airlock_vault::transport::pipe::{PipeAcl, create};
    use prompt_airlock_vault::win_sec;
    use tokio::net::windows::named_pipe::ClientOptions;

    fn unique_name(tag: &str) -> String {
        let mut b = [0u8; 8];
        prompt_airlock_vault::types::csprng_fill(&mut b).unwrap();
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        format!(r"\\.\pipe\pa-vault-test-{tag}-{hex}")
    }

    #[tokio::test]
    async fn current_user_dacl_has_single_ace() {
        let name = unique_name("acl");
        let p = create(&name, true, PipeAcl::CurrentUser, 4).unwrap();
        let sddl = win_sec::pipe_security_sddl(&p).unwrap();
        let sid = win_sec::current_user_sid().unwrap();
        eprintln!("pipe(current-user) security: {sddl}");
        // GENERIC_ALL 은 파일 객체에서 FILE_ALL_ACCESS(FA)로 매핑돼 표시된다.
        let dacl = sddl.split_once("D:").map(|x| x.1).unwrap_or_default();
        assert_eq!(dacl, format!("P(A;;FA;;;{sid})"), "{sddl}");
    }

    #[tokio::test]
    async fn default_dacl_is_reported() {
        let name = unique_name("default");
        let p = create(&name, true, PipeAcl::Default, 4).unwrap();
        let sddl = win_sec::pipe_security_sddl(&p).unwrap();
        // 측정용 출력. 판정은 보고서에서 한다.
        eprintln!("pipe(default) security: {sddl}");
        assert!(sddl.contains("D:"));
    }

    #[tokio::test]
    async fn first_instance_flag_blocks_squatting() {
        let name = unique_name("first");
        let _owner = create(&name, true, PipeAcl::CurrentUser, 4).unwrap();
        // 이미 같은 이름이 있으면 first_pipe_instance 생성은 실패해야 한다(이름 선점 감지).
        let err = create(&name, true, PipeAcl::CurrentUser, 4).unwrap_err();
        eprintln!("second first-instance create error: {err:?}");
    }

    #[tokio::test]
    async fn pipe_roundtrip() {
        let (ctx, _j) = ctx();
        let name = unique_name("rt");
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(transport::pipe::run(ctx, name, PipeAcl::CurrentUser, move |ep| {
            let _ = tx.send(ep);
        }));
        let ep = rx.await.unwrap();
        let mut c = ClientOptions::new().open(&ep).unwrap();
        assert!(matches!(common::call(&mut c, 1, common::hello(&SECRET)).await.result, Some(R::Hello(_))));
        assert!(matches!(common::call(&mut c, 2, common::create_scope(1000)).await.result, Some(R::CreateScope(_))));
        // 두 번째 동시 클라이언트
        let mut c2 = ClientOptions::new().open(&ep).unwrap();
        assert!(matches!(common::call(&mut c2, 1, common::hello(&SECRET)).await.result, Some(R::Hello(_))));
    }
}

#[cfg(unix)]
mod uds {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[tokio::test]
    async fn socket_permissions_and_roundtrip() {
        let (ctx, _j) = ctx();
        let mut b = [0u8; 8];
        prompt_airlock_vault::types::csprng_fill(&mut b).unwrap();
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("pa-vault-test-{hex}"));
        let path = dir.join("vault.sock");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let p2 = path.clone();
        let task = tokio::spawn(transport::uds::run(ctx, p2, move |ep| {
            let _ = tx.send(ep);
        }));
        rx.await.unwrap();
        let dir_mode = std::fs::metadata(&dir).unwrap().mode() & 0o777;
        let sock_mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
        eprintln!("uds dir mode={dir_mode:o} socket mode={sock_mode:o}");
        assert_eq!(dir_mode, 0o700);
        assert_eq!(sock_mode, 0o600);
        let mut s = tokio::net::UnixStream::connect(&path).await.unwrap();
        assert!(matches!(common::call(&mut s, 1, common::hello(&SECRET)).await.result, Some(R::Hello(_))));
        task.abort();
        let _ = task.await;
        // guard 가 소켓 파일을 지운다
        assert!(!path.exists());
        let _ = std::fs::remove_dir(&dir);
    }

    #[tokio::test]
    async fn group_accessible_directory_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let mut b = [0u8; 8];
        prompt_airlock_vault::types::csprng_fill(&mut b).unwrap();
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("pa-vault-test-open-{hex}"));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = transport::uds::bind(&dir.join("vault.sock"));
        assert!(r.is_err());
        let _ = std::fs::remove_dir(&dir);
    }
}
