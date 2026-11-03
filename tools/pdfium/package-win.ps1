# PDFium 빌드 결과를 우리 빌드가 읽는 모양으로 묶는다: <pkg>\include\*.h, <pkg>\lib\pdfium.lib, REVISION, SHA256SUMS, LICENSES\
$ErrorActionPreference = 'Stop'
$base = Join-Path $env:LOCALAPPDATA 'pa-pdfium'
$src = "$base\src\pdfium"
$pkg = "$base\pkg\windows-x64"
if (Test-Path $pkg) { Remove-Item -Recurse -Force $pkg }
New-Item -ItemType Directory -Force "$pkg\include\cpp", "$pkg\lib", "$pkg\LICENSES" | Out-Null
Copy-Item "$src\public\*.h" "$pkg\include\"
Copy-Item "$src\public\cpp\*.h" "$pkg\include\cpp\"
Copy-Item "$src\out\win-release\obj\pdfium.lib" "$pkg\lib\"
Copy-Item "$src\out\win-release\args.gn" "$pkg\args.gn"
Copy-Item "$src\LICENSE" "$pkg\LICENSES\pdfium.txt"
$utf8 = New-Object Text.UTF8Encoding $false  # CMake 가 읽는 파일이므로 BOM 없이 쓴다
[IO.File]::WriteAllText("$pkg\REVISION", (git -C $src log -1 --format='%H %cI') + "`n", $utf8)
Push-Location $pkg
$sums = @('lib\pdfium.lib') + (Get-ChildItem include\*.h | ForEach-Object { "include\$($_.Name)" }) | ForEach-Object {
    "$((Get-FileHash $_ -Algorithm SHA256).Hash.ToLower())  $($_ -replace '\\', '/')"
}
[IO.File]::WriteAllText("$pkg\SHA256SUMS", ($sums -join "`n") + "`n", $utf8)
Pop-Location
Get-Content "$pkg\REVISION"
Get-Content "$pkg\SHA256SUMS" -TotalCount 1
'{0:N0} bytes' -f (Get-ChildItem -Recurse $pkg -File | Measure-Object Length -Sum).Sum
