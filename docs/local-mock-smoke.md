# 로컬 mock 연동 확인

이 안내는 외부 provider 없이 새 임시 Gateway와 `mock-provider`를 연결해 첫 통과와 등급 차단을 확인합니다. 실사용 자격 증명이나 기관 자료를 넣지 않습니다. mock 기록은 가명 처리한 요청 본문을 담을 수 있으므로 접근이 제한된 임시 폴더에만 둡니다.

## Windows native 빌드 위치

저장소 루트의 PowerShell에서 Visual Studio 2022 x64 환경과 vcpkg를 설정하는 wrapper로 실행 파일을 빌드합니다.

```powershell
tools\win-dev.cmd cmake --build --preset win-debug --target prompt-airlock mock-provider --parallel 4
$BuildDir = Join-Path (Get-Location) 'build\win-debug'
$App = Join-Path $BuildDir 'apps\prompt-airlock\prompt-airlock.exe'
$Mock = Join-Path $BuildDir 'tools\mock-provider\mock-provider.exe'
```

이번 configure 출력과 실행 파일 경로는 `build/win-debug/` 아래였습니다. Windows C++ 실행은 PowerShell에서 하며 Visual Studio Open Folder는 이 smoke에서 사용하지 않습니다. CA·leaf 생성에 쓰는 OpenSSL CLI는 Windows C++ runtime dependency가 아닙니다. 현재 Git for Windows의 `usr\bin\openssl.exe` 3.2.4를 확인했고, 인증서 생성과 `s_client` 검증에만 사용합니다. 새 tool 설치는 하지 않습니다.

## 비공개 임시 폴더와 test CA

PowerShell에서 고유 디렉터리를 만들고 현재 사용자와 SYSTEM만 접근하도록 제한합니다. Windows native smoke의 인증서 생성과 TLS 확인은 설치된 Git for Windows OpenSSL CLI로 수행합니다. WSL 스크립트나 시스템 trust store는 사용하지 않습니다.

~~~powershell
$Demo = Join-Path $env:TEMP ('pa-local-mock-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Demo | Out-Null
icacls $Demo /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
$GitRoot = Split-Path (Split-Path (Get-Command git).Source -Parent) -Parent
$OpenSsl = Join-Path $GitRoot 'usr\bin\openssl.exe'
& $OpenSsl version
if ($LASTEXITCODE -ne 0) { throw 'Git for Windows OpenSSL is unavailable' }
$CertDir = Join-Path $Demo 'certs'
New-Item -ItemType Directory -Path $CertDir | Out-Null
$ExtensionLines = @(
  'subjectAltName = IP:127.0.0.1, DNS:localhost',
  'basicConstraints = critical,CA:FALSE',
  'keyUsage = critical,digitalSignature,keyEncipherment',
  'extendedKeyUsage = serverAuth'
)
[System.IO.File]::WriteAllLines((Join-Path $CertDir 'server.ext'), $ExtensionLines, [System.Text.Encoding]::ASCII)
& $OpenSsl req -x509 -newkey rsa:3072 -nodes -days 2 -subj '/CN=Prompt-Airlock-local-test-CA' -keyout (Join-Path $CertDir 'ca.key') -out (Join-Path $CertDir 'ca.pem') 2> (Join-Path $Demo 'openssl-ca.stderr')
if ($LASTEXITCODE -ne 0) { throw 'test CA generation failed' }
foreach ($Name in @('gateway', 'mock')) {
  & $OpenSsl req -newkey rsa:2048 -nodes -subj '/CN=localhost' -keyout (Join-Path $CertDir ($Name + '.key')) -out (Join-Path $CertDir ($Name + '.csr')) 2> (Join-Path $Demo ($Name + '-keygen.stderr'))
  if ($LASTEXITCODE -ne 0) { throw 'test leaf key generation failed' }
  & $OpenSsl x509 -req -days 2 -in (Join-Path $CertDir ($Name + '.csr')) -CA (Join-Path $CertDir 'ca.pem') -CAkey (Join-Path $CertDir 'ca.key') -CAcreateserial -extfile (Join-Path $CertDir 'server.ext') -out (Join-Path $CertDir ($Name + '.pem'))
  if ($LASTEXITCODE -ne 0) { throw 'test leaf generation failed' }
}
& $OpenSsl verify -CAfile (Join-Path $CertDir 'ca.pem') -verify_ip 127.0.0.1 (Join-Path $CertDir 'gateway.pem') (Join-Path $CertDir 'mock.pem')
if ($LASTEXITCODE -ne 0) { throw 'strict CA and IP verification failed' }
~~~

CA와 leaf는 이 ACL 제한 디렉터리에만 저장합니다. leaf SAN은 127.0.0.1과 localhost입니다. Git for Windows OpenSSL의 지정 CA/IP 검증만 사용하고 Windows trust store에는 추가하지 않습니다.

## 사전 점검

실행 전에 아래 명령으로 설정 파싱, 수신·provider TLS 자료, 보호된 HTTPS 자격 증명, 고정 모델 지문, 기관 정책, check 소유 Vault의 준비 상태를 확인할 수 있습니다.

~~~powershell
prompt-airlock check config.json
~~~

이 명령은 HTTP listener나 audit 파일을 만들지 않으며 provider 연결, CLI 실행, 요청 전송, 응답 검증은 하지 않습니다. provider_connection: not_tested와 provider_transfer: not_tested는 실제 연결·전송 동작을 확인하지 않았다는 뜻입니다. HTTPS provider는 보호된 자격 증명 파일만 읽고, local CLI provider는 설정된 실행 파일의 존재만 확인합니다.

실패는 고정 stage/code와 0이 아닌 종료값으로 보고하며 설정 경로, 자격 증명, 본문은 출력하지 않습니다.

## Gateway config와 protected request 파일

PowerShell에서 token을 한 번 발급하고 stdout을 보호 파일로 돌립니다. 두 번째 줄의 hash만 `config.json`에 넣고 첫 줄의 원문은 ACL이 제한된 파일에서만 읽습니다.

```powershell
$Issued = Join-Path $Demo 'secrets\issued-once.txt'
& $App issue-token local-demo > $Issued
if ($LASTEXITCODE -ne 0) { throw 'origin token generation failed' }
$IssuedLines = Get-Content -LiteralPath $Issued
$OriginToken = ($IssuedLines[0] -split ': ', 2)[1]
$TokenHash = [regex]::Match($IssuedLines[1], '"token_sha256": "([0-9a-f]{64})"').Groups[1].Value
if ($TokenHash.Length -ne 64) { throw 'token hash missing' }
$AuthLine = 'header = "Authorization: Bearer ' + $OriginToken + '"' + "`n"
[System.IO.File]::WriteAllText((Join-Path $Demo 'secrets\request-auth.curl'), $AuthLine, [System.Text.UTF8Encoding]::new($false))
$Config = [ordered]@{
  listen = [ordered]@{ address = '127.0.0.1'; port = 19743; certificate_chain = 'certs/gateway.pem'; private_key = 'certs/gateway.key' }
  provider = [ordered]@{ url = 'https://127.0.0.1:19744/v1/chat/completions'; credential_file = 'secrets/provider.key'; trust_file = 'certs/ca.pem'; model = 'synthetic' }
  origins = @([ordered]@{ name = 'local-demo'; token_sha256 = $TokenHash; grade_policy = 'o-only' })
  compat = [ordered]@{ chat_app = $true }
  internal_terms = @()
}
[System.IO.File]::WriteAllText((Join-Path $Demo 'config.json'), ($Config | ConvertTo-Json -Depth 8), [System.Text.UTF8Encoding]::new($false))
$PassJson = '{"model":"synthetic","messages":[{"role":"user","content":"Summarize user@example.test for this local check."}],"stream":false}'
$BlockedJson = '{"model":"synthetic","messages":[{"role":"user","content":"Summarize this local check."}],"stream":false}'
[System.IO.File]::WriteAllText((Join-Path $Demo 'pass.json'), $PassJson, [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText((Join-Path $Demo 'blocked.json'), $BlockedJson, [System.Text.UTF8Encoding]::new($false))
& $App protect-credential (Join-Path $Demo 'secrets\mock-credential') (Join-Path $Demo 'secrets\provider.key') > (Join-Path $Demo 'protect-credential.log') 2>&1
if ($LASTEXITCODE -ne 0) { throw 'provider credential protection failed' }
Remove-Item -LiteralPath $Issued
```

`request-auth.curl`는 curl이 bearer token을 명령 인자에 넣지 않도록 합니다. `config.json`에는 hash만 저장됩니다. mock용 plain credential은 test server에서만 읽고 Gateway provider credential은 Windows DPAPI로 보호합니다. token·credential은 URL, terminal output, screenshot에 넣지 않습니다.

Windows Schannel 기반 `curl.exe`는 임시 CA에 대해 폐지 상태를 확인할 수 없어 `CERT_TRUST_REVOCATION_STATUS_UNKNOWN`으로 끝날 수 있습니다. 검증을 완화하지 말고 Git for Windows의 OpenSSL `s_client`로 지정 CA와 IP를 검증합니다. 다음 요청 파일은 protected temp에 저장되며, OpenSSL은 stdin에서만 읽습니다.

```powershell
function New-HttpFile($Name, $Grade, $JsonPath) {
  $Body = [System.IO.File]::ReadAllText($JsonPath, [System.Text.Encoding]::UTF8)
  $Token = ($AuthLine -replace '^header = "Authorization: Bearer ', '') -replace '"\s*$', ''
  $Length = [System.Text.Encoding]::UTF8.GetByteCount($Body)
  $Request = "POST /v1/chat/completions HTTP/1.1`r`nHost: 127.0.0.1:19743`r`nConnection: close`r`nAuthorization: Bearer $Token`r`nContent-Type: application/json`r`nX-Prompt-Airlock-Grade: $Grade`r`nContent-Length: $Length`r`n`r`n$Body"
  [System.IO.File]::WriteAllText((Join-Path $Demo ($Name + '.request.http')), $Request, [System.Text.UTF8Encoding]::new($false))
}
New-HttpFile 'pass' 'O' (Join-Path $Demo 'pass.json')
New-HttpFile 'blocked' 'C' (Join-Path $Demo 'blocked.json')
$GitRoot = Split-Path (Split-Path (Get-Command git).Source -Parent) -Parent
$env:PA_LOCAL_OPENSSL = Join-Path $GitRoot 'usr\bin\openssl.exe'
& $env:PA_LOCAL_OPENSSL version
foreach ($Name in @('pass', 'blocked')) {
  $CmdLine = '"%PA_LOCAL_OPENSSL%" s_client -quiet -connect 127.0.0.1:19743 -CAfile certs\ca.pem -verify 3 -verify_ip 127.0.0.1 -verify_return_error < ' + $Name + '.request.http > ' + $Name + '.response.raw 2> ' + $Name + '.tls.stderr'
  $Cmd = @('@echo off', $CmdLine, 'exit /b %ERRORLEVEL%')
  [System.IO.File]::WriteAllLines((Join-Path $Demo ($Name + '.tls.cmd')), $Cmd, [System.Text.Encoding]::ASCII)
}
Remove-Variable OriginToken,AuthLine,Token
```

`pass.tls.cmd`와 `blocked.tls.cmd`는 OpenSSL 실행 파일 경로 외에는 각 test 파일 이름만 받습니다. 원문 token은 요청 파일 안에서만 존재하고 OpenSSL이 stdin으로 읽습니다. `-verify_return_error`, `-verify_ip 127.0.0.1`, `-CAfile`을 유지합니다. `-k`, revoke check 해제 옵션, 시스템 certificate import는 사용하지 않습니다.

## Windows native 첫 요청

PowerShell 창 1에서 mock, 창 2에서 Gateway를 실행합니다.

```powershell
& $Mock 127.0.0.1 19744 (Join-Path $Demo 'certs\mock.pem') (Join-Path $Demo 'certs\mock.key') (Join-Path $Demo 'secrets\mock-credential') (Join-Path $Demo 'mock-records.jsonl')
& $App serve (Join-Path $Demo 'config.json')
```

셋째 창에서 두 request 파일을 OpenSSL의 stdin으로 보냅니다.

```powershell
Push-Location $Demo
cmd.exe /d /c pass.tls.cmd
cmd.exe /d /c blocked.tls.cmd
Pop-Location
$PassRaw = [System.IO.File]::ReadAllText((Join-Path $Demo 'pass.response.raw'))
$BlockedRaw = [System.IO.File]::ReadAllText((Join-Path $Demo 'blocked.response.raw'))
$PassStatus = [regex]::Match($PassRaw, '^HTTP/1\.1 (\d{3})').Groups[1].Value
$BlockedStatus = [regex]::Match($BlockedRaw, '^HTTP/1\.1 (\d{3})').Groups[1].Value
$BlockedBody = [regex]::Split($BlockedRaw, "\r?\n\r?\n", 2)[1]
$BlockedDecision = ($BlockedBody | ConvertFrom-Json).prompt_airlock.decision
$MockCount = (Get-Content (Join-Path $Demo 'mock-records.jsonl') | Measure-Object -Line).Lines
$RawMarkerCount = (Select-String -LiteralPath (Join-Path $Demo 'mock-records.jsonl') -SimpleMatch 'user@example.test' | Measure-Object).Count
"pass_http=$PassStatus blocked_http=$BlockedStatus blocked_decision=$BlockedDecision mock_received=$MockCount raw_marker=$RawMarkerCount"
```

정상 O 요청은 HTTP 200·mock 수신 1건, 이후 C 등급 차단은 HTTP 200 안내·`blocked`·추가 mock 0건이어야 합니다. `raw_marker=0`이면 합성 email 원문은 mock 기록에 없습니다. 응답 본문과 record 내용을 콘솔에 표시하지 않습니다.

## WSL native 첫 요청

Windows PowerShell을 저장소 루트에서 열고 Ubuntu WSL login shell을 시작합니다. 아래 Bash 명령은 저장소 루트에서 실행합니다. 새 패키지는 설치하지 않으며 Windows DPAPI 파일은 WSL로 복사하지 않습니다.

~~~bash
set -euo pipefail
umask 077
REPO="$(git rev-parse --show-toplevel)"
cd "$REPO"
tools/wsl-dev.sh cmake --preset linux-gcc14
tools/wsl-dev.sh cmake --build --preset linux-gcc14 --target prompt-airlock mock-provider --parallel 4
BUILD_DIR="$HOME/.cache/prompt-airlock/main/linux-gcc14"
APP="$BUILD_DIR/apps/prompt-airlock/prompt-airlock"
MOCK="$BUILD_DIR/tools/mock-provider/mock-provider"
DEMO="$(mktemp -d /tmp/pa-local-mock.XXXXXX)"
chmod 700 "$DEMO"
mkdir -m 700 -p "$DEMO/certs" "$DEMO/secrets"
cat > "$DEMO/certs/server.ext" <<'EOF'
subjectAltName = IP:127.0.0.1, DNS:localhost
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF
openssl req -x509 -newkey rsa:3072 -nodes -days 2 -subj /CN=Prompt-Airlock-local-test-CA \
  -keyout "$DEMO/certs/ca.key" -out "$DEMO/certs/ca.pem" >/dev/null 2>"$DEMO/openssl-ca.stderr"
for NAME in gateway mock; do
  openssl req -newkey rsa:2048 -nodes -subj /CN=localhost \
    -keyout "$DEMO/certs/$NAME.key" -out "$DEMO/certs/$NAME.csr" >/dev/null 2>"$DEMO/$NAME-keygen.stderr"
  openssl x509 -req -days 2 -in "$DEMO/certs/$NAME.csr" \
    -CA "$DEMO/certs/ca.pem" -CAkey "$DEMO/certs/ca.key" -CAcreateserial \
    -extfile "$DEMO/certs/server.ext" -out "$DEMO/certs/$NAME.pem" >/dev/null
done
chmod 600 "$DEMO"/certs/*.key
openssl verify -CAfile "$DEMO/certs/ca.pem" -verify_ip 127.0.0.1 "$DEMO/certs/gateway.pem" "$DEMO/certs/mock.pem"
openssl rand -hex 32 > "$DEMO/secrets/mock-credential"
chmod 600 "$DEMO/secrets/mock-credential"
"$APP" issue-token local-demo > "$DEMO/secrets/issued-once.txt"
TOKEN="$(sed -n 's/^token (shown once, give it only to the origin app): //p' "$DEMO/secrets/issued-once.txt")"
TOKEN_HASH="$(sed -n 's/.*"token_sha256": "\([0-9a-f]\{64\}\)".*/\1/p' "$DEMO/secrets/issued-once.txt")"
test -n "$TOKEN"
test "$(printf '%s' "$TOKEN_HASH" | wc -c)" -eq 64
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" > "$DEMO/secrets/request-auth.curl"
chmod 600 "$DEMO/secrets/issued-once.txt" "$DEMO/secrets/request-auth.curl"
unset TOKEN
rm -- "$DEMO/secrets/issued-once.txt"
"$APP" protect-credential "$DEMO/secrets/mock-credential" "$DEMO/secrets/provider.key"
chmod 600 "$DEMO/secrets/provider.key"
cat > "$DEMO/config.json" <<EOF
{
  "listen": {"address":"127.0.0.1","port":19743,"certificate_chain":"certs/gateway.pem","private_key":"certs/gateway.key"},
  "provider": {"url":"https://127.0.0.1:19744/v1/chat/completions","credential_file":"secrets/provider.key","trust_file":"certs/ca.pem","model":"synthetic"},
  "origins": [{"name":"local-demo","token_sha256":"$TOKEN_HASH","grade_policy":"o-only"}],
  "compat": {"chat_app":true},
  "internal_terms": []
}
EOF
chmod 600 "$DEMO/config.json"
cat > "$DEMO/pass.json" <<'EOF'
{"model":"synthetic","messages":[{"role":"user","content":"Contact d4-wsl-native-20261124@example.test. Marker WSL-NATIVE-SAFE-01."}],"stream":false}
EOF
cat > "$DEMO/blocked.json" <<'EOF'
{"model":"synthetic","messages":[{"role":"user","content":"Synthetic classification check."}],"stream":false}
EOF
printf '%s\n' 'd4-wsl-native-20261124@example.test' > "$DEMO/secrets/raw-email-marker.txt"
chmod 600 "$DEMO/pass.json" "$DEMO/blocked.json" "$DEMO/secrets/raw-email-marker.txt"
APP_PID=
MOCK_PID=
cleanup() {
  if test -n "$APP_PID"; then kill -TERM "$APP_PID" 2>/dev/null || true; fi
  if test -n "$MOCK_PID"; then kill -TERM "$MOCK_PID" 2>/dev/null || true; fi
  if test -n "$APP_PID"; then wait "$APP_PID" 2>/dev/null || true; fi
  if test -n "$MOCK_PID"; then wait "$MOCK_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM
"$MOCK" 127.0.0.1 19744 "$DEMO/certs/mock.pem" "$DEMO/certs/mock.key" \
  "$DEMO/secrets/mock-credential" "$DEMO/mock-records.jsonl" > "$DEMO/mock.log" 2>&1 &
MOCK_PID=$!
"$APP" serve "$DEMO/config.json" > "$DEMO/gateway.log" 2>&1 &
APP_PID=$!
curl --noproxy '*' --cacert "$DEMO/certs/ca.pem" --silent --show-error \
  --retry 12 --retry-connrefused --retry-delay 1 --max-time 2 --output /dev/null \
  https://127.0.0.1:19743/console
PASS_HTTP="$(curl --noproxy '*' --cacert "$DEMO/certs/ca.pem" --silent --show-error \
  --config "$DEMO/secrets/request-auth.curl" -H 'X-Prompt-Airlock-Grade: O' \
  -H 'Content-Type: application/json' --data-binary "@$DEMO/pass.json" \
  --output "$DEMO/pass.response.raw" --write-out '%{http_code}' \
  https://127.0.0.1:19743/v1/chat/completions)"
MOCK_AFTER_PASS="$(wc -l < "$DEMO/mock-records.jsonl" | tr -d '[:space:]')"
if grep -F -q -f "$DEMO/secrets/raw-email-marker.txt" "$DEMO/mock-records.jsonl"; then RAW_EMAIL=1; else RAW_EMAIL=0; fi
BLOCKED_HTTP="$(curl --noproxy '*' --cacert "$DEMO/certs/ca.pem" --silent --show-error \
  --config "$DEMO/secrets/request-auth.curl" -H 'X-Prompt-Airlock-Grade: C' \
  -H 'Content-Type: application/json' --data-binary "@$DEMO/blocked.json" \
  --output "$DEMO/blocked.response.raw" --write-out '%{http_code}' \
  https://127.0.0.1:19743/v1/chat/completions)"
MOCK_AFTER_BLOCK="$(wc -l < "$DEMO/mock-records.jsonl" | tr -d '[:space:]')"
if grep -q '"decision"[[:space:]]*:[[:space:]]*"blocked"' "$DEMO/blocked.response.raw"; then BLOCKED_DECISION=blocked; else BLOCKED_DECISION=unexpected; fi
test "$PASS_HTTP" = 200
test "$BLOCKED_HTTP" = 200
test "$MOCK_AFTER_PASS" = 1
test "$MOCK_AFTER_BLOCK" = 1
test "$RAW_EMAIL" = 0
printf 'pass_http=%s blocked_http=%s blocked_decision=%s mock_after_pass=%s mock_after_block=%s raw_email_hits=%s\n' \
  "$PASS_HTTP" "$BLOCKED_HTTP" "$BLOCKED_DECISION" "$MOCK_AFTER_PASS" "$MOCK_AFTER_BLOCK" "$RAW_EMAIL"
cleanup
trap - EXIT INT TERM
case "$DEMO" in
  /tmp/pa-local-mock.*) rm -r -- "$DEMO" ;;
  *) printf '%s\n' 'unexpected temp path; review manually' >&2; exit 1 ;;
esac
~~~

curl의 Authorization 헤더는 보호된 request-auth.curl 파일에서 읽습니다. CA 검증은 --cacert와 URL의 127.0.0.1 IP 확인으로 유지하고, -k/시스템 trust 변경은 쓰지 않습니다. 정상 O 요청 뒤 local mock은 1건, C 차단 뒤 추가 요청 0건이어야 합니다. mock 기록 전체나 응답 본문 대신 마지막 줄의 숫자와 상태만 기록하세요. Gateway의 provider credential은 protect-credential이 만든 Linux Vault 파일만 사용하고 mock의 평문 자격 파일은 시험 서버만 읽습니다.

Windows native와 WSL smoke는 Gateway API와 로컬 mock 경계만 확인합니다. LibreChat의 승인 링크는 브라우저 시나리오에서 별도로 확인하고, 첨부 요청도 같은 로컬 Gateway로만 보냅니다.
