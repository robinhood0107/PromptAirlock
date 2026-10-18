//! 실행 파일 시험: READY 한 줄 형식, stdin 이 닫히면 종료, TCP transport 요청 거절(ADR 0003).

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

const EXE: &str = env!("CARGO_BIN_EXE_prompt-airlock-vault");

#[test]
fn ready_line_then_exit_on_stdin_close() {
    let mut child = Command::new(EXE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("vault 실행");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(fields[0], "PA-VAULT-READY");
    assert_eq!(fields[1], "v=1");
    let transport = if cfg!(windows) { "transport=pipe" } else { "transport=uds" };
    assert_eq!(fields[2], transport);
    assert!(fields[3].starts_with("endpoint="));
    assert_eq!(fields[4], format!("pid={}", child.id()));
    let secret = fields[5].strip_prefix("secret=").unwrap();
    assert_eq!(secret.len(), 64);
    assert!(secret.bytes().all(|b| b.is_ascii_hexdigit()));

    // 부모가 stdin 을 닫으면 Vault 는 스스로 끝난다.
    drop(child.stdin.take());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait());
    });
    let status = rx.recv_timeout(Duration::from_secs(10)).expect("stdin 을 닫아도 끝나지 않음").unwrap();
    assert!(status.success(), "{status:?}");
}

#[test]
fn tcp_transport_is_rejected() {
    let status = Command::new(EXE)
        .args(["--transport", "tcp"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}
