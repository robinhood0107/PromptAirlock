#!/usr/bin/env bash
# Git Bash 에서 Windows preset workflow 를 실행한다. 예: tools/build.sh win-release
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
cmd.exe //c "tools\win-dev.cmd cmake --workflow --preset ${1:-win-release}"
