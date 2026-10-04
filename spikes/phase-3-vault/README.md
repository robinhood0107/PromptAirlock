# Phase 3 spike — Rust Secure Mapping Vault / IPC

최종 저장소 구조가 아니다. Phase 3 판정 근거를 만들기 위한 실험 코드다. 값은 모두 합성 데이터다.

## 구성
- `proto/vault_v1.proto` — 버전 고정 IPC 스키마(`prompt_airlock.vault.v1`). 4바이트 big-endian 길이 + protobuf, 최대 frame 64 KiB.
- `vault/` — Rust Vault(lib + `prompt-airlock-vault` 실행 파일). single-owner actor, bounded queue, TTL, zeroize, TCP·Named Pipe·UDS.
- `ffi-learning/` — 학습용 cdylib. 같은 주소 공간 위험을 보이는 용도이며 운영 경로에 쓰지 않는다.
- `cpp-client/` — C++23 클라이언트(`std::expected`, RAII, timeout), E2E 시험, 벤치마크.
- `tools/win-dev.cmd`, `tools/wsl-dev.sh` — Phase 1 과 같은 환경 래퍼.

## 고정 명령
CMake 구성 단계에서 vcpkg 가 protobuf(protoc 포함)를 설치하고, 빌드 단계에서 그 protoc 로 `cargo build --release --locked` 를 실행한다. `ctest` 에 `cargo test --release` 가 포함된다.

```
Windows (저장소 루트에서):
  cd spikes\phase-3-vault
  tools\win-dev.cmd cmake --workflow --preset win-release
  tools\win-dev.cmd cmake --workflow --preset win-asan
  build\win-release\cpp-client\pa_vault_bench.exe target\release\prompt-airlock-vault.exe

WSL:
  cd spikes/phase-3-vault
  tools/wsl-dev.sh cmake --workflow --preset wsl-gcc14
  tools/wsl-dev.sh cmake --workflow --preset wsl-clang-tsan
  ~/.cache/prompt-airlock/phase-3/wsl-gcc14/cpp-client/pa_vault_bench ~/.cache/prompt-airlock/phase-3/target/release/prompt-airlock-vault
```

cargo 만 따로 돌릴 때는 `PROTOC` 에 vcpkg 가 만든 protoc 경로를 지정한다.
예: `PROTOC=build/win-release/vcpkg_installed/x64-windows/tools/protobuf/protoc.exe cargo test --locked`.

빌드 출력: `build/<preset>`, `target/`(Windows), `~/.cache/prompt-airlock/phase-3/`(WSL). 모두 추적하지 않는다.

## Vault 실행 계약
```
prompt-airlock-vault --transport <pipe|tcp|uds> [--pipe-acl current-user|default] [한도 옵션]
stdout 한 줄: PA-VAULT-READY v=1 transport=<..> endpoint=<..> pid=<n> secret=<64 hex>
```
- 비밀값은 실행마다 새로 만들며 부모의 stdout 파이프로만 전달한다(명령줄·환경변수 미사용).
- 연결의 첫 요청은 `hello(secret)` 이어야 한다.
- stdin 이 닫히면(부모 종료) Vault 도 종료하고 모든 mapping 을 zeroize 한다. 메모리 상태만 있으므로 재시작하면 이전 token 은 복원되지 않는다.
