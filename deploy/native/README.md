# 로컬 설치 묶음

이 경로는 검증된 네이티브 빌드에서 Gateway, 문서 추출 자식 프로세스, Rust Vault, NER 파일과 vcpkg 저작권 고지를 복사합니다. 시작할 때 설치 묶음의 manifest와 `bin/`, `libexec/`, `share/` 배치를 확인해 실행 파일 옆의 고정 자원 경로를 사용합니다. manifest가 없는 개발 트리에서는 기존 CMake 경로를 사용합니다.

## Windows

저장소 루트에서 `tools/win-dev.cmd cmake --workflow --preset win-debug`를 실행한 뒤, 비어 있는 새 목적지에 묶음을 만듭니다.

```powershell
$build = (Resolve-Path '.\build\win-debug').Path
$install = Join-Path $env:LOCALAPPDATA 'PromptAirlock'
powershell -File .\deploy\native\windows\Install-PromptAirlock.ps1 -BuildRoot $build -Destination $install
powershell -File (Join-Path $install 'Start-PromptAirlock.ps1') -Config '<합성 또는 승인된 config.json 경로>'
```

이 후보에는 Windows Service Control Manager 진입점이 없어 Windows 서비스 등록을 지원하지 않습니다. PowerShell 시작 스크립트는 콘솔 프로세스를 실행하고, 종료는 해당 프로세스의 정상 종료로 처리합니다. 서비스 등록 권한을 높이거나 가짜 서비스로 시험하지 않습니다.

## WSL 사용자 서비스

WSL 로그인 셸에서 `tools/wsl-dev.sh cmake --workflow --preset linux-gcc14`를 실행한 다음 패키지와 사용자 데이터 디렉터리를 준비합니다.

```bash
build="$HOME/.cache/prompt-airlock/main/linux-gcc14"
install="$HOME/.local/lib/prompt-airlock"
data="$HOME/.local/share/prompt-airlock"
bash deploy/native/linux/package.sh "$build" "$install"
install -d -m 700 "$data" "$HOME/.config/systemd/user"
install -m 644 "$install/prompt-airlock.service" "$HOME/.config/systemd/user/prompt-airlock.service"
```

`$data/config.json`과 그 파일이 참조하는 `certs/`, `secrets/`를 운영자가 안전한 권한으로 준비합니다. WSL systemd 사용자 관리자가 실행 중일 때 다음 명령으로 서비스를 관리합니다.

```bash
systemctl --user daemon-reload
systemctl --user enable --now prompt-airlock.service
systemctl --user restart prompt-airlock.service
systemctl --user stop prompt-airlock.service
```

사용자 서비스는 `%h/.local/lib/prompt-airlock`에 설치된 실행 파일과 Vault·NER 자원을 사용하고, 설정과 audit 경로는 `$data` 아래에 둡니다. `systemctl --user`가 동작하지 않는 WSL 구성에서는 user unit을 검증된 것으로 간주하지 않습니다.
