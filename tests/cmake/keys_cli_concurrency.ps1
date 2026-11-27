param(
    [Parameter(Mandatory = $true)][string]$App,
    [Parameter(Mandatory = $true)][string]$ConfigFile
)

$ErrorActionPreference = 'Stop'

function Start-OriginAdd([string]$OriginName) {
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $App
    $info.Arguments = 'keys add "' + $ConfigFile + '" ' + $OriginName
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'start_failed' }
    return $process
}

try {
    $first = Start-OriginAdd 'process-a'
    $second = Start-OriginAdd 'process-b'

    if (-not $first.WaitForExit(30000)) { $first.Kill(); throw 'first_timeout' }
    if (-not $second.WaitForExit(30000)) { $second.Kill(); throw 'second_timeout' }
    $firstOutput = $first.StandardOutput.ReadToEnd()
    $firstError = $first.StandardError.ReadToEnd()
    $secondOutput = $second.StandardOutput.ReadToEnd()
    $secondError = $second.StandardError.ReadToEnd()

    $firstMatch = [regex]::Match($firstOutput, '\Atoken: ([A-Za-z0-9_-]{43})\r?\n?\z')
    $secondMatch = [regex]::Match($secondOutput, '\Atoken: ([A-Za-z0-9_-]{43})\r?\n?\z')
    if ($first.ExitCode -ne 0 -or $second.ExitCode -ne 0 -or $firstError.Length -ne 0 -or $secondError.Length -ne 0 -or
        -not $firstMatch.Success -or -not $secondMatch.Success) {
        throw 'child_failed'
    }

    $tokens = @($firstMatch.Groups[1].Value, $secondMatch.Groups[1].Value)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $document = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
    $rawConfig = [System.IO.File]::ReadAllText($ConfigFile)
    foreach ($index in 0..1) {
        $name = if ($index -eq 0) { 'process-a' } else { 'process-b' }
        $entry = @($document.origins | Where-Object { $_.name -eq $name })
        if ($entry.Count -ne 1 -or $entry[0].grade_policy -ne 'o-only') { throw 'entry_missing' }
        $tokenBytes = [System.Text.Encoding]::UTF8.GetBytes($tokens[$index])
        $hashBytes = $hasher.ComputeHash($tokenBytes)
        $expectedHash = [System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
        if ($entry[0].token_sha256 -ne $expectedHash -or $rawConfig.Contains($tokens[$index])) { throw 'entry_invalid' }
    }
    $hasher.Dispose()
    Write-Output 'keys_process_concurrency=passed'
    exit 0
} catch {
    if ($null -ne $first -and -not $first.HasExited) { $first.Kill() }
    if ($null -ne $second -and -not $second.HasExited) { $second.Kill() }
    if ($null -ne $hasher) { $hasher.Dispose() }
    [Console]::Error.WriteLine('keys_process_concurrency=failed')
    exit 1
}
