# PDFium 소스 받기(Windows, 저장소 밖). depot_tools 의 Python 은 여기서만 쓴다(결정 #229).
# Linux 와 같은 판(b75764a1)으로 맞춘다. 설치된 Visual Studio 를 쓴다(DEPOT_TOOLS_WIN_TOOLCHAIN=0).
$ErrorActionPreference = 'Stop'
$base = Join-Path $env:LOCALAPPDATA 'pa-pdfium'
New-Item -ItemType Directory -Force $base | Out-Null
Set-Location $base
if (-not (Test-Path depot_tools)) { git clone --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git }
$env:PATH = "$base\depot_tools;$env:PATH"
$env:DEPOT_TOOLS_WIN_TOOLCHAIN = '0'
git -C depot_tools log -1 --format='depot_tools %H %cI'
New-Item -ItemType Directory -Force src | Out-Null
Set-Location src
if (-not (Test-Path .gclient)) { cmd /c gclient config --unmanaged --custom-var=checkout_configuration=minimal https://pdfium.googlesource.com/pdfium.git }
cmd /c gclient sync --no-history --shallow -j8 --revision pdfium@b75764a1def138ff0f308c637865f195774ccdc4
git -C pdfium log -1 --format='pdfium %H %cI'
