param([Parameter(Mandatory = $true)][string]$Config)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$configPath = (Resolve-Path -LiteralPath $Config).Path
Push-Location (Split-Path -Parent $configPath)
try {
    & (Join-Path $root 'bin\prompt-airlock.exe') serve $configPath
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
