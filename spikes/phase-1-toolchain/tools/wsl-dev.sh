#!/usr/bin/env bash
# WSL 에서 vcpkg 경로를 잡은 뒤 인자로 받은 명령을 실행한다.
# 예: tools/wsl-dev.sh cmake --workflow --preset wsl-gcc14
set -euo pipefail
export VCPKG_ROOT="${VCPKG_ROOT:-$HOME/dev/vcpkg}"
exec "$@"
