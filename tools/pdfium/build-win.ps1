# PDFium 정적 라이브러리 빌드(Windows, 저장소 밖 %LOCALAPPDATA%\pa-pdfium). 결정 #229: depot_tools 의 Python 은 여기서만 쓴다.
# 받기: tools/pdfium/fetch-win.ps1. 설치된 Visual Studio 2022 와 Windows SDK 10.0.28000 을 쓴다(DEPOT_TOOLS_WIN_TOOLCHAIN=0).
$ErrorActionPreference = 'Stop'
$base = Join-Path $env:LOCALAPPDATA 'pa-pdfium'
$env:PATH = "$base\depot_tools;$env:PATH"
$env:DEPOT_TOOLS_WIN_TOOLCHAIN = '0'
Set-Location "$base\src\pdfium"
git log -1 --format='pdfium %H %cI'
$utf8 = New-Object Text.UTF8Encoding $false  # gn 과 Python 은 BOM 을 읽지 못한다
# 우리 빌드는 동적 CRT(/MD)다. 정적 빌드의 기본 CRT(/MT)를 동적으로 바꾸는 빌드 설정 한 줄만 고친다(PDFium 코드는 그대로).
git -C build checkout -- config/win/BUILD.gn vs_toolchain.py toolchain/win/setup_toolchain.py  # 앞선 시도의 SDK 판 고침도 되돌림
$crt = 'build/config/win/BUILD.gn'
$text = (Get-Content $crt -Raw) -replace '(# Desktop Windows: static CRT\.\s*\n\s*)configs = \[ ":static_crt" \]', '$1configs = [ ":dynamic_crt" ]'
[IO.File]::WriteAllText((Resolve-Path $crt), $text, $utf8)
git -C build diff --stat
$out = 'out/win-release'
New-Item -ItemType Directory -Force $out | Out-Null
@'
is_debug = false
is_component_build = false
target_cpu = "x64"
pdf_is_standalone = true
pdf_is_complete_lib = true
pdf_enable_v8 = false
pdf_enable_xfa = false
pdf_use_skia = false
use_custom_libcxx = false
treat_warnings_as_errors = false
clang_use_chrome_plugins = false
symbol_level = 0
pdf_use_partition_alloc = false
use_partition_alloc = false
use_allocator_shim = false
use_partition_alloc_as_malloc = false
'@ | Set-Content -Encoding ascii "$out/args.gn"
cmd /c gn gen $out
if ($LASTEXITCODE -ne 0) { throw 'gn gen failed' }
$sw = [Diagnostics.Stopwatch]::StartNew()
cmd /c ninja -C $out pdfium
if ($LASTEXITCODE -ne 0) { throw 'ninja failed' }
"build seconds $([int]$sw.Elapsed.TotalSeconds)"
Get-Item "$out/obj/pdfium.lib" | Select-Object Length
(Get-FileHash "$out/obj/pdfium.lib" -Algorithm SHA256).Hash.ToLower()
