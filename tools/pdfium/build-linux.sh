#!/usr/bin/env bash
# PDFium 정적 라이브러리 빌드(Linux, 저장소 밖). 결정 #229: depot_tools 의 Python 은 여기서만 쓴다.
set -eu
base=$HOME/.cache/prompt-airlock/pdfium
export PATH="$base/depot_tools:$PATH"
cd "$base/src/pdfium"
git log -1 --format='pdfium %H %cI'
out=out/linux-release
# GNU ld(우리 gcc·clang 빌드)는 ELF CREL 재배치를 읽지 못한다. Chromium 빌드 설정의 CREL 켜는 줄만 지운다(PDFium 코드는 그대로).
git -C build checkout -- config/compiler/BUILD.gn
sed -i "/-Wa,--crel,--allow-experimental-crel/d" build/config/compiler/BUILD.gn
git -C build diff --stat
mkdir -p $out
cat > $out/args.gn <<'ARGS'
is_debug = false
is_component_build = false
pdf_is_standalone = true
pdf_is_complete_lib = true
pdf_enable_v8 = false
pdf_enable_xfa = false
pdf_use_skia = false
use_custom_libcxx = false
treat_warnings_as_errors = false
clang_use_chrome_plugins = false
symbol_level = 0
# 추출기는 주소 공간을 1 GiB 로 스스로 제한한다. Chromium 할당기(PartitionAlloc)와 malloc 대체는 큰 주소 영역을 예약하므로 끈다.
pdf_use_partition_alloc = false
use_partition_alloc = false
use_allocator_shim = false
use_partition_alloc_as_malloc = false
ARGS
gn gen $out
time ninja -C $out pdfium
ls -la $out/obj/libpdfium.a
sha256sum $out/obj/libpdfium.a
gn desc $out //:pdfium deps --all | grep -o '^//third_party/[a-z0-9_]*' | sort -u
