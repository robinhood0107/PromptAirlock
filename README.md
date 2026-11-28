# Prompt Airlock

외부 LLM으로 보내는 프롬프트의 개인정보를 가명 token으로 바꾸고 응답에서 원래 값을 복원하는 보안 중계 Gateway입니다. HTTPS API, 별도 프로세스의 Rust Vault, 문서 검사, 미리보기와 로컬 승인을 제공합니다. 코드 구조는 [구성 안내](docs/structure.md), 외부 의존성은 [의존성과 라이선스](docs/dependencies.md), 설계 결정은 [ADR 목록](docs/adr/README.md)에 있습니다.

## 구성

| 경로 | 내용 |
|---|---|
| `src/`, `include/` | C++23 Gateway |
| `vault/` | 별도 프로세스의 Rust Secure Mapping Vault |
| `proto/` | Gateway와 Vault 사이 IPC 정의 |
| `tests/` | 단위·통합·속성·퍼즈 시험 |
| `cmake/`, `tools/` | 빌드 설정과 개발 wrapper |
| `spikes/` | 사전 실험 코드, 제품 빌드에 포함하지 않음 |

## 네이티브 빌드와 시험

Docker 없이 C++23 Gateway와 Rust Vault를 빌드하고 시험할 수 있습니다. 새 PC에서는 저장소를 복제한 뒤 저장소 루트에서 아래 OS별 도구를 준비합니다.

```bash
git clone https://github.com/robinhood0107/PromptAirlock.git
cd PromptAirlock
```

### 새 Windows/Ubuntu 개발 환경

Windows에는 Visual Studio 2022 Community 또는 Build Tools의 Desktop development with C++ workload, Windows SDK, LLVM clang-cl이 필요합니다. Ubuntu/WSL에서는 GCC 14와 g++-14를 사용하며 sanitizer/fuzz preset에는 clang++-23도 필요합니다. 두 OS 모두 CMake 3.28 이상, Ninja, Git, Rust stable과 Cargo가 필요합니다. 도구는 각 공급자의 공식 설치 안내로 준비하고, 이 저장소의 빌드 wrapper에 시스템 PATH 변경은 필요하지 않습니다.

vcpkg manifest와 Cargo.lock이 의존성 판을 고정합니다. 아래 절차는 공식 vcpkg 저장소를 사용하고 이 저장소의 baseline `19780d9cdf84d0944cf9a318666703b89ab6629c`로 checkout합니다. bootstrap telemetry는 끄며 `VCPKG_ROOT`는 현재 터미널 세션에만 설정합니다.

이미 준비된 한 Windows/Ubuntu WSL 호스트에서 CLI를 검증했습니다. 확인한 판은 Visual Studio Community 2022 17.14, Windows CMake 4.4.3/Ninja 1.13.2/Git 2.49.0/Rust 1.99.0, Ubuntu WSL CMake 4.4.3/Ninja 1.11.1/Git 2.43.0/Rust 1.99.0/g++-14 14.2.0/clang++-23 23.1.2이며 두 vcpkg checkout은 manifest baseline과 일치했습니다. 이번 작업에서 도구 설치·업그레이드, 새 Windows/Ubuntu 설치, 별도 깨끗한 OS VM 검증은 하지 않았습니다.

### Windows

새 사용자에게는 관리자 소유 기본 경로 대신 쓰기 가능한 사용자 디렉터리를 권합니다. 같은 PowerShell 창에서 vcpkg를 준비하고 configure/build/ctest를 실행합니다.

```powershell
$env:VCPKG_ROOT = Join-Path $HOME 'src\PromptAirlock\vcpkg'
if (-not (Test-Path (Join-Path $env:VCPKG_ROOT '.git'))) {
  New-Item -ItemType Directory -Force -Path (Split-Path $env:VCPKG_ROOT) | Out-Null
  git clone https://github.com/microsoft/vcpkg.git $env:VCPKG_ROOT
}
git -C $env:VCPKG_ROOT checkout 19780d9cdf84d0944cf9a318666703b89ab6629c
& (Join-Path $env:VCPKG_ROOT 'bootstrap-vcpkg.bat') -disableMetrics
git -C $env:VCPKG_ROOT rev-parse HEAD

tools\win-dev.cmd cmake --preset win-debug
tools\win-dev.cmd cmake --build --preset win-debug --parallel 4
tools\win-dev.cmd ctest --preset win-debug
```

전체 workflow를 쓸 때는 다음 명령 하나로 configure/build/ctest를 실행합니다.

```powershell
tools\win-dev.cmd cmake --workflow --preset win-debug
```

wrapper는 Visual Studio 2022 x64 환경을 현재 프로세스에만 설정하고 VCPKG_ROOT를 보존합니다. Visual Studio Open Folder UI는 preset을 표시하지만 이 문서의 검증은 CLI로 했으며 IDE 화면은 실행하지 않았습니다.

### Ubuntu Linux 또는 WSL

Ubuntu WSL login shell에서 vcpkg baseline과 C++ 도구를 준비한 뒤 같은 저장소 루트에서 build/test를 실행합니다. WSL vcpkg는 사용자 홈 아래의 checkout을 사용합니다.

```bash
export VCPKG_ROOT="$HOME/dev/vcpkg"
if [ ! -d "$VCPKG_ROOT/.git" ]; then
  mkdir -p "$HOME/dev"
  git clone https://github.com/microsoft/vcpkg.git "$VCPKG_ROOT"
fi
git -C "$VCPKG_ROOT" checkout 19780d9cdf84d0944cf9a318666703b89ab6629c
"$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics
git -C "$VCPKG_ROOT" rev-parse HEAD

tools/wsl-dev.sh cmake --preset linux-gcc14
tools/wsl-dev.sh cmake --build --preset linux-gcc14 --parallel 4
tools/wsl-dev.sh ctest --preset linux-gcc14
```

전체 workflow는 다음과 같습니다.

```bash
tools/wsl-dev.sh cmake --workflow --preset linux-gcc14
```

linux-clang-asan-ubsan, linux-clang-tsan, linux-clang-fuzz도 지원합니다. fuzz preset의 기본 길이는 대상마다 60초입니다. CTest에는 Rust Vault의 cargo test --locked가 포함됩니다. WSL wrapper는 login shell에서 실행하고 VCPKG_ROOT는 그 세션에만 적용합니다.

### 실행 파일과 첫 mock 요청

Windows win-debug 실행 파일은 build/win-debug/apps/prompt-airlock/prompt-airlock.exe와 같은 폴더의 prompt-airlock-extract.exe, build/win-debug/tools/mock-provider/mock-provider.exe입니다. WSL linux-gcc14 build root는 $HOME/.cache/prompt-airlock/main/linux-gcc14이고 Gateway와 mock 실행 파일은 apps/prompt-airlock/ 및 tools/mock-provider/ 아래에 있습니다.

보호된 합성 config, test CA, `request-auth.curl` 생성, 엄격한 TLS 확인, 첫 O 요청·C 차단 및 local mock 실행 절차는 [로컬 mock 연동 가이드](docs/local-mock-smoke.md)에 있습니다. 네이티브 설치 묶음과 WSL user service는 [로컬 설치 안내](deploy/native/README.md), 전체 로컬 Compose는 [LibreChat 배포 안내](deploy/librechat/README.md)를 참고합니다. LibreChat은 선택적 컨테이너 경로이며 native 빌드에는 Docker가 필요하지 않습니다.

## 로컬 콘솔과 채팅 앱

[로컬 콘솔](docs/local-console.md)은 미리보기, 문서 검사, 연결 상태, 확인 목록과 관리자 조회를 제공합니다. 파일 입력과 제한은 [문서 파일 입력](docs/file-input.md)에 있습니다. Open WebUI와 Chatbox는 설치하지 않고, 기존 Chat Completions API의 로컬 연결만 [호환 앱 연결 안내](docs/compatible-chat-apps.md)에서 설명합니다.

LibreChat는 선택적 외부 앱이며 공식 이미지를 수정하거나 제품에 포함하지 않습니다. 앱과 MongoDB만 로컬 compose 프로젝트로 실행하는 절차, 저장·보존·백업 안내는 [LibreChat 배포 안내](deploy/librechat/README.md)를 확인하세요.

## 라이선스

[AGPL-3.0-only](LICENSE)

기관 내 설치에서 소스 공개 의무가 없는 사용 조건은 별도 상용 라이선스 대상입니다. 배포는 설치형으로 제한하며 기준은 [ADR 0024](docs/adr/0024-license-and-distribution.md)에 있습니다. 제품 배포에 포함하는 라이브러리와 모델의 고지는 [제3자 고지](THIRD_PARTY_NOTICES.md)에 있습니다.

Copyright (C) 2026 robinhood0107
