param(
    [Parameter(Mandatory = $true)][string]$Destination,
    [string]$BuildRoot
)

$ErrorActionPreference = 'Stop'
$stage = 'resolve_build'

try {
    $repository = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
    if (-not $BuildRoot) {
        $BuildRoot = Join-Path $repository 'build\win-debug'
    }
    $BuildRoot = (Resolve-Path -LiteralPath $BuildRoot).Path
    $stage = 'validate_build'
    $appSource = Join-Path $BuildRoot 'apps\prompt-airlock'
    $vaultSource = Join-Path $BuildRoot 'cargo\release\prompt-airlock-vault.exe'
    $modelSource = Join-Path $BuildRoot 'models\ner'
    if (-not (Test-Path (Join-Path $appSource 'prompt-airlock.exe')) -or
        -not (Test-Path (Join-Path $appSource 'prompt-airlock-extract.exe')) -or
        -not (Test-Path $vaultSource) -or -not (Test-Path (Join-Path $modelSource 'model.onnx'))) {
        throw 'build_incomplete'
    }

    $destination = [IO.Path]::GetFullPath($Destination)
    $stage = 'prepare_destination'
    if (Test-Path -LiteralPath $destination) {
        if (@(Get-ChildItem -LiteralPath $destination -Force).Count -ne 0) {
            throw 'destination_not_empty'
        }
    } else {
        New-Item -ItemType Directory -Path $destination | Out-Null
    }

    $bin = Join-Path $destination 'bin'
    $libexec = Join-Path $destination 'libexec'
    $models = Join-Path $destination 'share\models\ner'
    $licenses = Join-Path $destination 'share\licenses'
    $stage = 'copy_runtime'
    New-Item -ItemType Directory -Path $bin, $libexec, $models, $licenses | Out-Null
    foreach ($runtimeFile in @('prompt-airlock.exe', 'prompt-airlock-extract.exe')) {
        Copy-Item -LiteralPath (Join-Path $appSource $runtimeFile) -Destination $bin
    }
    foreach ($runtimeDll in Get-ChildItem -LiteralPath $appSource -File -Filter '*.dll') {
        Copy-Item -LiteralPath $runtimeDll.FullName -Destination $bin
    }
    Copy-Item -LiteralPath $vaultSource -Destination (Join-Path $libexec 'prompt-airlock-vault.exe')
    Copy-Item -Path (Join-Path $modelSource '*') -Destination $models -Recurse
    Copy-Item -LiteralPath (Join-Path $repository 'LICENSE') -Destination (Join-Path $licenses 'PromptAirlock-LICENSE')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Start-PromptAirlock.ps1') -Destination $destination

    $stage = 'copy_onnx_notices'
    $ortConfig = [IO.File]::ReadAllText((Join-Path $repository 'cmake\OnnxRuntime.cmake'))
    $ortMatch = [regex]::Match($ortConfig, '(?m)^set\(PA_ORT_VERSION ([^)]+)\)')
    if (-not $ortMatch.Success) {
        throw 'onnx_version_missing'
    }
    $ortRoot = Join-Path $repository ('_deps\onnxruntime-win-x64-' + $ortMatch.Groups[1].Value)
    $ortLicense = Join-Path $licenses 'onnxruntime'
    New-Item -ItemType Directory -Path $ortLicense | Out-Null
    foreach ($notice in @('LICENSE', 'ThirdPartyNotices.txt')) {
        $source = Join-Path $ortRoot $notice
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw 'onnx_license_missing'
        }
        Copy-Item -LiteralPath $source -Destination $ortLicense
    }

    $stage = 'read_vcpkg_install'
    $cache = [IO.File]::ReadAllText((Join-Path $BuildRoot 'CMakeCache.txt'))
    $match = [regex]::Match($cache, '(?m)^VCPKG_INSTALLED_DIR:PATH=([^\r\n]+)')
    if (-not $match.Success) {
        throw 'vcpkg_install_missing'
    }
    $installed = $match.Groups[1].Value.Trim()
    if (-not [IO.Path]::IsPathRooted($installed)) {
        $installed = Join-Path $BuildRoot $installed
    }
    $share = Join-Path $installed 'x64-windows\share'
    $stage = 'copy_vcpkg_notices'
    foreach ($package in Get-ChildItem -LiteralPath $share -Directory) {
        $copyright = Join-Path $package.FullName 'copyright'
        if (Test-Path -LiteralPath $copyright -PathType Leaf) {
            $packageLicense = Join-Path $licenses ('vcpkg\' + $package.Name)
            New-Item -ItemType Directory -Path $packageLicense -Force | Out-Null
            Copy-Item -LiteralPath $copyright -Destination $packageLicense
        }
    }

    $stage = 'hash_package_files'
    $hashes = foreach ($file in Get-ChildItem -LiteralPath $destination -File -Recurse) {
        $relative = $file.FullName.Substring($destination.Length).TrimStart('\', '/') -replace '\\', '/'
        '{0}  {1}' -f (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
    }
    $stage = 'write_manifest'
    [IO.File]::WriteAllLines((Join-Path $destination 'manifest.sha256'), $hashes)
    $stage = 'complete'
    exit 0
} catch {
    [Console]::Error.WriteLine('package_failed stage=' + $stage)
    exit 1
}
