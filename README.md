# Prompt Airlock

외부 LLM에 보내는 프롬프트에서 개인정보를 가명 token으로 바꾸고, 응답을 원래 값으로 되돌리는 보안 중계 Gateway입니다. 현재 아키텍처를 동결하고 본 구현을 시작하는 단계입니다. 설계 결정은 [docs/adr](docs/adr/README.md)에 있습니다.

## 구성

| 경로 | 내용 |
|---|---|
| `src/`, `include/` | C++23 Gateway |
| `vault/` | Rust Secure Mapping Vault (별도 프로세스) |
| `proto/` | Gateway와 Vault 사이 IPC 정의 |
| `tests/` | 시험 |
| `cmake/`, `tools/` | 빌드 설정과 개발 환경 wrapper |
| `spikes/` | 사전 실험 코드, 제품 빌드에 포함하지 않음 |

## 빌드와 시험

필요한 도구: CMake 3.28 이상, Ninja, vcpkg(`VCPKG_ROOT`), Rust stable. Windows는 Visual Studio 2022 빌드 도구와 LLVM clang-cl, Linux는 gcc-14 또는 clang-23.

Windows

```
tools\win-dev.cmd cmake --workflow --preset win-release
```

preset: `win-debug`, `win-release`, `win-asan`

Linux

```
tools/wsl-dev.sh cmake --workflow --preset linux-gcc14
```

preset: `linux-gcc14`, `linux-clang-asan-ubsan`, `linux-clang-tsan`

workflow preset은 configure, build, test를 차례로 실행하며 Rust Vault의 `cargo test --locked`도 함께 실행합니다. Windows에서는 `tools\win-dev.cmd`를 거쳐야 Visual Studio 환경과 vcpkg 경로가 맞게 잡힙니다.

## License

[AGPL-3.0-only](LICENSE)

Copyright (C) 2026 robinhood0107
