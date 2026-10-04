# 0003. Vault IPC 스키마와 transport

상태: 확정 (2026-10-05)

## 결정

스키마와 framing

- Protobuf proto3, package `prompt_airlock.vault.v1`, 정의는 `proto/vault_v1.proto`.
- 4바이트 big-endian 길이 다음에 메시지 하나. frame 최대 64 KiB.
- op는 CreateScope, CreateToken, ResolveExact, DropScope 네 가지.
- 연결의 첫 메시지는 hello다. Vault가 실행마다 만든 32바이트 비밀값을 Gateway가 돌려보낸다. 비밀값은 자식 프로세스 stdout 파이프로만 전달한다.
- 모든 응답에 request_id를 되돌려 확인한다.
- 오류 응답에는 오류 코드만 싣는다. 버전 불일치, 해석할 수 없는 바이트, 과대 frame, 인증 실패는 오류 응답 뒤 연결을 닫는다.

transport

- Windows: Named Pipe. 현재 사용자 SID 하나만 허용하는 보호 DACL, 원격 클라이언트 거부, 첫 인스턴스만 생성, 클라이언트는 서버 pid가 자신이 띄운 프로세스인지 확인.
- Linux: Unix domain socket. 0700 디렉터리 안의 0600 소켓, SO_PEERCRED로 상대 uid와 pid 확인.
- TCP loopback은 쓰지 않는다.

## 대안

- TCP loopback: 구현이 가장 짧다(서버 12줄).
- Named Pipe 기본 DACL.
- 고정 struct를 그대로 보내는 바이너리 형식.

## 근거

측정은 release 빌드, 같은 PC, 각 op 2000회.

| transport | CreateToken p50 / p95 | 16 클라이언트 처리량 |
|---|---|---|
| Windows Named Pipe | 54.8 / 74.1 µs | 237k ops/s |
| Windows TCP loopback | 73.0 / 95.1 µs | 115k ops/s |
| WSL UDS | 115.6 / 161.5 µs | 64k ops/s |

- WSL 수치는 가상화 영향을 받으므로 같은 OS 안 비교에만 쓴다.
- Named Pipe 기본 DACL을 실제로 읽어 보니 Everyone과 Anonymous에 읽기 권한이 있었다.
- TCP는 같은 머신의 다른 사용자가 접속을 시도할 수 있고, 클라이언트가 서버 신원을 확인할 방법이 없다.
- 과대 frame, 잘못된 버전, 임의 바이트, 잘린 frame을 보내도 Vault는 오류를 반환하고 계속 동작했다.

## 보안 영향

- OS 계정 경계와 서버 신원 확인으로 다른 사용자나 가짜 서버가 mapping에 접근하는 경로를 줄인다.
- Windows DACL 설정에 Windows API 호출용 unsafe 코드 16곳이 필요하다. 한 모듈에 모으고 각 지점에 안전 조건을 적는다.
- Named Pipe 경로에서는 tokio/mio 내부 4 KiB 읽기·쓰기 버퍼 4개가 원문을 지우지 않은 채 해제된다. Vault 프로세스 안의 잔류이며 현 단계에서는 한계로 둔다. 상태 경로와 UDS 경로에서는 잔류가 없었다.

## 변경 조건

- 메모리 덤프 위협을 다루는 hardening 단계에서 Named Pipe 버퍼 잔류를 없애야 하면 자체 overlapped I/O로 바꾼다.
- 스키마를 바꿀 때는 package 버전을 올린다(v2). v1과 v2를 섞어 받지 않는다.
