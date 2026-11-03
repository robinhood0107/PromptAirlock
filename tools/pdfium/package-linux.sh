#!/usr/bin/env bash
# PDFium 빌드 결과를 우리 빌드가 읽는 모양으로 묶는다: <pkg>/include/*.h, <pkg>/lib/libpdfium.a, REVISION, SHA256SUMS, LICENSES/
set -eu
base=$HOME/.cache/prompt-airlock/pdfium
src=$base/src/pdfium
pkg=$base/pkg/linux-x64
rm -rf "$pkg" && mkdir -p "$pkg/include" "$pkg/lib" "$pkg/LICENSES"
cp "$src"/public/*.h "$pkg/include/"
mkdir -p "$pkg/include/cpp" && cp "$src"/public/cpp/*.h "$pkg/include/cpp/"
cp "$src/out/linux-release/obj/libpdfium.a" "$pkg/lib/"
git -C "$src" log -1 --format='%H %cI' > "$pkg/REVISION"
cp "$src/out/linux-release/args.gn" "$pkg/args.gn"
cp "$src/LICENSE" "$pkg/LICENSES/pdfium.txt"
(cd "$pkg" && sha256sum lib/libpdfium.a include/*.h > SHA256SUMS)
cat "$pkg/REVISION"; head -1 "$pkg/SHA256SUMS"; du -sh "$pkg"
