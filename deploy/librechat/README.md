# LibreChat 로컬 배포

이 선택 경로는 변경하지 않은 공식 LibreChat v0.8.9 prerelease 이미지와 MongoDB 8.0.20 공식 이미지를 사용합니다. Compose는 `api`와 `mongodb` 두 서비스만 시작합니다. Meilisearch, RAG API와 검색·공유 서비스를 실행하지 않습니다. Gateway의 정식 설치 묶음은 Phase 13 범위이며 여기서 새 Gateway 이미지를 빌드하지 않습니다.

Compose의 API 이미지 digest는 승인된 공식 이미지 인덱스 digest이며, MongoDB 이미지도 8.0.20 인덱스 digest로 고정했습니다. LibreChat의 upstream `librechat.yaml` schema version은 이 이미지의 `CONFIG_VERSION`인 `1.3.19`와 맞췄습니다. 이미지 참조는 [compose.yaml](compose.yaml) 한 곳에서 확인하세요. LibreChat 이미지를 수정·복제·재배포하지 않습니다. MongoDB 이미지도 저장소 배포물에 포함하지 않으며 운영자가 공식 이미지를 직접 가져옵니다.

## 로컬 시작

1. 기존 Docker Desktop Linux engine과 Compose v2를 준비합니다. 이 구성은 host network를 사용하므로 Docker engine에서 WSL Gateway와 loopback을 공유할 수 있어야 합니다. 외부 주소나 공개 포트를 설정하지 않습니다.
2. Gateway 운영자는 기존 출처 등록 절차로 `librechat` 출처를 등록하고 `o-only` 정책을 적용합니다. 출처 token은 기존 자격 증명 경로로 한 번만 전달합니다. 별도 관리자 권한이나 새 등급 설정을 만들지 않습니다.
3. Gateway는 `127.0.0.1:18743`의 HTTPS 입구를 사용하고 mock 예시는 `127.0.0.1:18744`에 둡니다. 실제 운영에서는 기관이 승인한 게이트웨이 주소·인증서만 설정합니다. Gateway CA 인증서는 `gateway-ca.pem`으로 두고 이미지 안의 Node 런타임에만 읽기 전용으로 마운트합니다. OS trust store 변경이나 인증서 검증 완화는 하지 않습니다.
4. `.env.example`을 `.env`로 복사하고 모든 자리표시자를 새 난수로 바꿉니다. `JWT_SECRET`과 `JWT_REFRESH_SECRET`은 각각 독립적인 32바이트 이상 난수로 만듭니다. `CREDS_KEY`는 32바이트(64 hex 문자), `CREDS_IV`는 16바이트(32 hex 문자)로 만듭니다. `openssl rand -hex 32`와 `openssl rand -hex 16` 출력이 이 형식에 맞습니다. MongoDB root와 LibreChat용 계정에도 서로 다른 URL-safe 난수 암호를 사용합니다. `PROMPT_AIRLOCK_TOKEN`에는 승인된 Gateway 출처 token을 둡니다. PowerShell에서는 `icacls .env /inheritance:r /grant:r "$($env:USERNAME):(F)" "SYSTEM:(F)"`를 적용하고, Linux 셸에서는 `umask 077; chmod 600 .env`를 적용합니다. 이 파일과 인증서 파일은 `.gitignore` 대상입니다.
5. 최초 관리자 계정 생성 때만 `.env`의 `ALLOW_REGISTRATION=true`로 바꿉니다. 기본 설정은 등록을 닫습니다.
6. `deploy/librechat/`에서 고정 digest 이미지를 가져와 설정을 확인하고 실행합니다.

```bash
docker compose --project-name librechat-local pull api mongodb
docker compose --project-name librechat-local config --quiet
docker compose --project-name librechat-local up --pull never -d
```

브라우저는 `http://127.0.0.1:3080`으로 접속합니다. MongoDB는 `127.0.0.1:27017`에만 bind하며 API도 `127.0.0.1:3080`에만 listen합니다. Compose는 host port mapping을 만들지 않습니다. 합성 계정을 만든 직후 `.env`의 `ALLOW_REGISTRATION=false`로 바꾸고 `docker compose --project-name librechat-local up --no-deps --force-recreate --pull never -d api`로 API만 다시 생성합니다. Gateway HTTPS endpoint는 웹 브라우저의 앱 URL과 scheme·port가 다른, 등록된 로컬 Gateway 주소입니다. `ENDPOINTS=custom`으로 Gateway 호환 endpoint만 노출하고 RUM·Scarf telemetry를 끕니다. 외부 언어모델 주소, 외부 검색, RAG와 Meilisearch는 설정하지 않습니다.

`librechat.yaml`은 upstream schema version `1.3.19`를 사용합니다. custom endpoint의 공식 `dropParams`로 `stream`, `user`, `frequency_penalty`, `presence_penalty`를 제거해 Gateway 허용 필드만 보내고, `addParams.maxRetries: 0`으로 앱 내부 재시도를 끕니다. v0.8.9의 Agents 화면은 별도로 stream 요청을 쓰므로 새 대화마다 `Parameters` → `Disable Streaming`을 켭니다. 이 선택은 현재 대화에만 적용되고 `New chat`에서는 꺼집니다. custom endpoint의 파일 전달은 직접 provider 경로를 선택하므로 업로드가 RAG 서비스로 가지 않고 Gateway에서 다시 검사됩니다. 기본 모델 이름은 Gateway가 고정 provider 별칭으로 교체합니다. healthcheck는 MongoDB의 인증 없는 읽기 전용 `ping`만 실행하며 root 암호를 인자에 넣지 않습니다.

차단·확인 요청의 LibreChat API HTTP 상태와 Gateway 판정은 구분해서 봅니다. 앱의 HTTP 200은 보호된 provider 왕복 성공을 뜻하지 않습니다. 승인 후 원래 출처와 같은 본문을 한 번 다시 보내며, Gateway는 보호 단계를 다시 거칩니다. 승인, 차단, 미리보기, 설정과 상태 점검은 외부 provider를 직접 호출하지 않습니다.

## 저장, 보존, 백업과 복구

MongoDB의 `mongodb_data` volume에는 계정, 대화와 업로드 메타데이터가 저장됩니다. `librechat_uploads` volume에는 앱이 보관하는 첨부 파일이 남을 수 있습니다. Gateway의 감사·egress 이력은 설정된 로컬 S급 경계에 별도로 저장합니다. LibreChat의 원문 대화 저장은 Gateway의 가명화 저장과 다릅니다.

Compose는 LibreChat 대화나 첨부에 자동 만료 기간을 설정하지 않습니다. 기관 운영자가 보존 기간, 계정 접근, 삭제 절차를 정하고 만료된 대화와 업로드를 같은 운영 절차로 정리해야 합니다. 두 volume과 비밀 설정을 기관이 지정한 저장소 수준 암호화로 보호하고, 백업에는 접근 통제와 별도 암호화를 적용합니다. 이 Compose는 OS 암호화, Mongo TLS, 계정 정책을 바꾸지 않습니다.

백업은 maintenance host의 공식 MongoDB Database Tools로 `LibreChat` DB를 archive 형식으로 저장합니다. Mongo 접속 URI를 쉘 인자, URL, 로그에 넣지 말고 접근이 제한된 config 파일을 사용합니다. 첨부 보존이 필요하면 `librechat_uploads`도 같은 백업 시각에 읽기 전용으로 별도 보관합니다. 백업 파일은 저장소 밖에 두고 암호화된 저장 위치로 옮깁니다.

복구 시험은 운영 volume을 재사용하지 않고 새 빈 Mongo volume과 새 빈 upload volume에 수행합니다. MongoDB 재시작 전후의 collection 수를 확인하고, 복구 뒤 계정·대화·첨부 수가 저장 전 집계와 일치하는지 확인합니다. 실제 본문을 출력하지 않습니다. 기존 시험에서는 MongoDB 8.0.20의 재시작, 66개 문서의 archive 백업과 별도 빈 volume 복구가 통과했습니다. 새로운 OS VM의 첫 설치는 검증 범위가 아닙니다.

## 닫기와 지원 범위

```bash
docker compose --project-name librechat-local down
```

`-v`를 더하면 이 프로젝트의 DB와 업로드 volume이 지워집니다. 보존할 데이터가 있는 운영 환경에서 사용하지 않습니다. Compose는 외부 제공자, 공개 demo, RAG, 원격 관리, system-wide TLS 또는 network 설정을 추가하지 않습니다.

검증된 범위는 기존 Windows Docker Desktop Linux engine과 같은 호스트의 Ubuntu WSL Gateway를 잇는 로컬 synthetic run입니다. 새 Windows·Ubuntu VM의 설치, 기관 네트워크, storage encryption 설정과 별도 호스트 접근 정책은 확인하지 않았습니다.