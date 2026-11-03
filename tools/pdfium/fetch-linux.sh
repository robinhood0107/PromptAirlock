#!/usr/bin/env bash
# PDFium 소스 받기(Linux, 저장소 밖 캐시). depot_tools 의 Python 은 여기서만 쓴다(결정 #229).
set -eu
base=$HOME/.cache/prompt-airlock/pdfium
mkdir -p "$base"
cd "$base"
[ -d depot_tools ] || git clone --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH="$base/depot_tools:$PATH"
git -C depot_tools log -1 --format='depot_tools %H %cI'
mkdir -p src && cd src
[ -f .gclient ] || gclient config --unmanaged --custom-var=checkout_configuration=minimal https://pdfium.googlesource.com/pdfium.git
gclient sync --no-history --shallow -j8 --revision pdfium@b75764a1def138ff0f308c637865f195774ccdc4
git -C pdfium log -1 --format='pdfium %H %cI'
du -sh "$base"
