# 0002. 언어와 프로세스 경계

상태: 확정 (2026-10-05)

## 결정

- Gateway는 C++23으로 작성한다.
- 원문과 가명 token의 mapping은 Rust로 작성한 Vault가 소유하며 Vault는 별도 프로세스다.
- Gateway가 Vault를 자식 프로세스로 띄우고 관리한다. 사용자는 Vault를 직접 실행하지 않는다.
- tokenizer도 C++로 구현한다. Rust 라이브러리를 Gateway 프로세스에 링크하지 않는다.

## 대안

- Rust 라이브러리(cdylib)를 Gateway 주소 공간에 로드하는 FFI 방식.

## 근거

- FFI 실험에서 Rust 쪽에 맡긴 32바이트 비밀값을 C++ 쪽이 자기 프로세스 메모리를 훑어 찾을 수 있었다(release 빌드 1개, ASan 빌드 2개 발견). 같은 주소 공간에서는 C++ 메모리 오류가 Rust가 보관한 값 전체를 노출할 수 있다.
- FFI 경계에는 Rust 쪽 unsafe 코드가 13곳 필요했다.
- 별도 프로세스 왕복 비용은 Windows Named Pipe 기준 CreateToken p50 54.8 µs, p95 74.1 µs였다.

## 보안 영향

- 운영체제 주소 공간 분리로 Gateway의 메모리 오류가 mapping 저장소로 번지지 않는다.
- Vault는 네트워크 접근과 provider 자격 증명이 필요 없다.

## 변경 조건

- 요청당 token 수가 많아 IPC 지연이 예산을 넘으면 먼저 일괄 조회 op를 추가한다. FFI로 바꾸는 것은 고려하지 않는다.
