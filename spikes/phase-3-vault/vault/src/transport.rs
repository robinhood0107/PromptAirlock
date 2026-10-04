//! Local IPC transport. 모두 같은 `serve_connection` 을 쓰고 접근 제어만 다르다.
//! - TCP: 127.0.0.1 에만 bind, 비루프백 peer 거절. 접근 제어는 hello 비밀값뿐(같은 머신의 모든 사용자가 접속 시도 가능).
//! - Windows Named Pipe: 원격 클라이언트 거절, 첫 인스턴스 플래그(이름 선점 방지), DACL 선택(기본/현재 사용자).
//! - Linux UDS: 0700 디렉터리 + 소켓 0600 + peer uid 확인.

use std::io;
use std::sync::Arc;

use crate::server::{ServerContext, serve_connection};

pub async fn run_tcp(ctx: Arc<ServerContext>, ready: impl FnOnce(String)) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    ready(listener.local_addr()?.to_string());
    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let _ = stream.set_nodelay(true);
        tokio::spawn(serve_connection(stream, ctx.clone()));
    }
}

#[cfg(windows)]
pub mod pipe {
    use super::*;
    use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PipeAcl {
        /// 운영체제 기본 보안 설명자(lpSecurityAttributes = NULL).
        Default,
        /// 현재 사용자 SID 하나에만 GENERIC_ALL 을 주는 보호된 DACL.
        CurrentUser,
    }

    pub fn create(name: &str, first: bool, acl: PipeAcl, max_instances: usize) -> io::Result<NamedPipeServer> {
        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first)
            .reject_remote_clients(true)
            .pipe_mode(PipeMode::Byte)
            .max_instances(max_instances.clamp(1, 254));
        match acl {
            PipeAcl::Default => opts.create(name),
            PipeAcl::CurrentUser => crate::win_sec::create_pipe_current_user(&opts, name),
        }
    }

    pub async fn run(
        ctx: Arc<ServerContext>,
        name: String,
        acl: PipeAcl,
        ready: impl FnOnce(String),
    ) -> io::Result<()> {
        let max = ctx.cfg.max_connections + 1;
        let mut server = create(&name, true, acl, max)?;
        ready(name.clone());
        loop {
            server.connect().await?;
            let connected = server;
            server = create(&name, false, acl, max)?;
            tokio::spawn(serve_connection(connected, ctx.clone()));
        }
    }
}

#[cfg(unix)]
pub mod uds {
    use super::*;
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    /// 소켓 파일을 지우는 guard. 종료 시 경로를 남기지 않는다.
    pub struct SocketGuard(PathBuf);

    impl Drop for SocketGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// 0700 디렉터리를 만들고(이미 있으면 권한을 확인) 소켓을 0600 으로 bind 한다.
    pub fn bind(path: &Path) -> io::Result<(tokio::net::UnixListener, SocketGuard, u32)> {
        let dir = path.parent().ok_or_else(|| io::Error::other("socket path has no parent"))?;
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let meta = std::fs::metadata(dir)?;
        if meta.mode() & 0o077 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "socket directory is group/other accessible"));
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        let guard = SocketGuard(path.to_path_buf());
        std::fs::set_permissions(path, Permissions::from_mode(0o600))?;
        let owner_uid = std::fs::metadata(path)?.uid();
        Ok((listener, guard, owner_uid))
    }

    pub async fn run(ctx: Arc<ServerContext>, path: PathBuf, ready: impl FnOnce(String)) -> io::Result<()> {
        let (listener, _guard, owner_uid) = bind(&path)?;
        ready(path.display().to_string());
        loop {
            let (stream, _) = listener.accept().await?;
            // 소켓 소유자와 다른 uid 의 peer 는 거절한다(권한 설정이 잘못돼도 2차 방어).
            match stream.peer_cred() {
                Ok(c) if c.uid() == owner_uid => {}
                _ => continue,
            }
            tokio::spawn(serve_connection(stream, ctx.clone()));
        }
    }
}
