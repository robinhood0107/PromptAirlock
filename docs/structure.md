# 코드 구조

Prompt Airlock은 기관 직원과 외부 언어모델(LLM) 사이에 서는 중계 프로그램(Gateway)이다.
질문에서 보내면 안 되는 값(주민등록번호, 비밀 키, 계좌번호 등)을 찾으면 요청을 막는다.
이름·전화번호·이메일처럼 바꿔서 보낼 수 있는 값은 가명 token(`⟦EMAIL_3K7Q...⟧` 모양의 대체 문자열)으로 바꾼다.
token과 원래 값의 짝은 별도 프로세스인 Vault에만 메모리로 보관한다.
LLM의 답이 오면 token을 원래 값으로 되돌려 직원에게 준다.

이 문서는 저장소에 있는 코드만 설명한다. 설계 결정의 이유는 [docs/adr](adr/README.md)에 있다.

## 요청 하나의 흐름

아래 순서는 아직 HTTP 서버(Phase 8)가 없어서 실제 서비스로는 돌지 않는다.
지금은 `tests/e2e/vault_pipeline_test.cpp`가 실제 탐지기, 실제 Vault, 가짜 provider(외부 LLM 대신 답을 흉내 내는 시험 코드)로 이 순서를 처음부터 끝까지 돌린다.
각 단계는 실패하면 요청 전체를 거절한다(fail closed: 확인이 안 되면 통과시키지 않고 막는다).

1. 등급 확정: `resolve_grade` (`core/grade.hpp`). 요청의 기관 분류 등급이 O(공개)일 때만 `OpenGrade` 증표를 만든다. C·S·미확정은 거절한다.
2. 입력 묶기: `RequestParams::create` (`core/request_params.hpp`), `PromptDocumentBuilder::build` (`core/document.hpp`), `RawPrompt::create` (`core/prompt.hpp`). 메시지와 파라미터를 검사해 원문 질문 `RawPrompt`를 만든다.
3. 탐지: `Detectors::detect` (`detect/detectors.hpp`). 문서 전체에서 개인정보·비밀 위치(`EntitySpan`)와 인코딩 덩어리(`EncodedFinding`)를 찾는다. 판정은 하지 않는다.
4. 정책 검사: `check_policy` (`core/policy.hpp`). 탐지 위치를 문서와 다시 맞춰 보고, 차단 종류가 하나라도 있으면 거절한다. 통과하면 겹친 결과를 합쳐 `PolicyCheckedPrompt`를 만든다.
5. Vault 범위 열기: `VaultService::open_scope` (`vault_client/service.hpp`). 이 요청 전용 범위(scope) `VaultScope`를 연다. 범위는 요청 하나의 token만 담는 칸이다.
6. 보호: `protect` (`core/privacy.hpp`). 바꿀 자리마다 `VaultScope::issue`로 token을 받고 `apply_protection`으로 텍스트를 다시 써 `ProtectedPrompt`를 만든다. 원문 묶음은 이때 지워진다.
7. 잔여 검사: 보호 후 문서를 `Detectors::detect`로 다시 탐지하고 `verify_residual` (`core/residual.hpp`)에 넘긴다. 남은 대상이 없고 인코딩 판정(`judge_encoded`)도 통과해야 `VerifiedPrompt`가 된다.
8. 외부 요청 만들기: `make_provider_request` (`core/provider_boundary.hpp`). `VerifiedPrompt`만 받는 유일한 입구다. `ProviderRequest`를 만든다.
9. provider 호출: 지금은 시험의 가짜 provider가 답을 돌려준다. 실제 호출 코드는 아직 없다.
10. 응답 검사: 응답을 `Detectors::detect`로 탐지하고 `check_response` (`core/restore.hpp`)에 넘긴다. 차단 종류의 값이 응답에 있으면 거절한다. 통과하면 `CheckedResponse`가 된다.
11. 복원 계획: `plan_restore` (`core/restore.hpp`). `scan_tokens`로 token을 찾고, `check_link_contexts`로 token이 링크·주소 안에 있으면 거절한다.
12. 복원: `apply_restore` (`core/restore.hpp`). token마다 `VaultScope::resolve`로 원래 값을 받아 끼워 넣는다. 하나라도 못 풀면 응답 전체를 거절한다.
13. 정리: `VaultScope`가 소멸하면서 Vault의 범위를 지운다(`drop_scope`).

거절은 모두 `Rejection` (`core/reason.hpp`)으로 끝난다. 사용자에게는 사유 코드만, 감사용 정보에는 위치만 남고 원문 값은 어디에도 담지 않는다.

## 폴더 한눈에

| 폴더 | 하는 일 |
|---|---|
| `include/prompt_airlock/core/`, `src/core/` | 도메인 타입과 판정 함수. 파일·네트워크·시계·난수를 쓰지 않는다 |
| `include/prompt_airlock/detect/`, `src/detect/` | 규칙 기반(결정론) 탐지기. core에만 의존한다 |
| `src/detect/data/` | 탐지 형식표와 단어 사전. 항목마다 출처 주석이 있다 |
| `include/prompt_airlock/vault_client/`, `src/vault_client/` | Vault 프로세스 실행, IPC 연결, 연결 풀. core에만 의존한다 |
| `include/prompt_airlock/tls/`, `src/tls/` | TLS 설정. 협상 범위가 고정이고, OpenSSL 설정을 직접 부르는 곳은 여기뿐이다 |
| `include/prompt_airlock/gateway/`, `src/gateway/` | HTTP 입구: 설정 파일, 출처 인증, 오류 응답, HTTPS 서버, 요청 JSON 읽기, 처리 단계 |
| `include/prompt_airlock/provider/`, `src/provider/` | provider HTTPS 클라이언트. provider 주소와 자격 증명은 여기만 가진다 |
| `tools/mock-provider/` | 시험·시연용 mock provider. 받은 요청을 기록하고 질문을 인용해 답한다. 운영 빌드에 넣지 않는다 |
| `vault/` | Rust로 만든 Vault 프로세스(Cargo workspace) |
| `proto/` | Gateway와 Vault가 함께 쓰는 IPC 메시지 정의 |
| `cmake/` | 빌드 옵션, 검사 스크립트, Vault 빌드 연결 |
| `tools/` | 개발 환경 wrapper와 표 생성 도구 |
| `tests/` | 시험(단위, property, 빌드 실패, fuzz, e2e, 측정, purity) |
| `docs/adr/` | 설계 결정 기록 |
| `.github/`, `.githooks/` | CI, 공개 텍스트 검사, 이슈·PR 양식 |
| `spikes/` | 본 구현 전 실험 코드. 제품 빌드에 넣지 않는다 |

## core

라이브러리 `prompt_airlock_core`. 입출력(I/O)이 없는 순수 코드다. 다른 모듈에 의존하지 않고, 다른 모듈이 core에 의존한다.
경고를 오류로 다루며, `tests/purity`가 금지 include(파일, 시계, 난수, 정규식 등)를 검사한다.

질문은 네 단계 타입으로만 바뀐다: `RawPrompt`, `PolicyCheckedPrompt`, `ProtectedPrompt`, `VerifiedPrompt`.
다음 단계는 정해진 core 함수만 만들 수 있다. 이를 위해 생성자에 열쇠(passkey) `StateKey`를 요구한다. 단계 타입은 복사되지 않고 넘겨지기만 한다.

| 파일 | 하는 일 | 주요 타입·함수 |
|---|---|---|
| `core/types.hpp` | 공용 열거형과 고정 처리표 | `DataGrade`, `GradePolicy`, `Action`, `EntityType`(17종), `MessageRole`, `DetectorKind`, `EncodingKind`, `default_action`, `stricter`, `EntityTypeSet`, `SegmentIndex`, `max_prompt_bytes`, `max_entities` |
| `core/error.hpp` | 단계별 오류 종류 | `InputError`, `DetectError`, `ProtectionError`, `VaultError`, `ResidualError`, `RestoreError`, `CoreError` |
| `core/offset.hpp` | 위치 종류별로 다른 타입. 섞어 쓰면 빌드되지 않는다 | `Offset<Tag>`, `Utf8ByteOffset`, `CodepointOffset`, `TokenOffset`, `ByteSpan` |
| `core/utf8.hpp`, `utf8.cpp` | 엄격한 UTF-8 검증과 위치 변환 | `validate_utf8`, `decode_utf8`, `DecodedCodepoint`, `check_span`, `is_codepoint_boundary`, `to_codepoint_offset`, `to_byte_offset` |
| `core/sensitive.hpp`, `sensitive.cpp` | 원문을 담는 상자. 복사 불가, 소멸 때 메모리를 0으로 덮는다 | `SensitiveText`, `SensitiveText::copy_of`, `secure_wipe` |
| `core/grade.hpp`, `grade.cpp` | 기관 분류 등급 확정 | `OpenGrade`, `parse_grade_mark`, `resolve_grade` |
| `core/request_params.hpp`, `request_params.cpp` | 출력 길이·temperature 등 파라미터 범위 검사 | `OutputTokenCap`, `RequestParamsInput`, `RequestParams::create`, `ResponseFormat` |
| `core/document.hpp`, `document.cpp` | 검사 대상 묶음(메시지와 stop 문자열) | `Segment`, `SegmentSource`, `MessageSource`, `StopSource`, `ContentForm`, `PromptDocument`, `PromptDocumentBuilder` |
| `core/entity.hpp`, `entity.cpp` | 탐지 결과 한 건. 만들 때 위치를 검증한다 | `EntitySpan::make` |
| `core/merge.hpp`, `merge.cpp` | 겹친 탐지 결과를 합치고 가장 엄격한 처리를 고른다 | `MergedEntity`, `merge_entities` |
| `core/prompt.hpp`, `prompt.cpp` | 질문의 네 단계 타입 | `RawPrompt`, `PolicyCheckedPrompt`, `ProtectedPrompt`, `VerifiedPrompt`, `Replacement` |
| `core/policy.hpp`, `policy.cpp` | 요청 동안 바뀌지 않는 정책과 정책 검사 | `Policy::standard`, `Policy::research`, `check_policy` |
| `core/strategy.hpp` | 가명화 전략. 운영은 항상 `UniquePseudonym` | `PrivacyStrategy`, `PrivacyStrategyKind` |
| `core/privacy.hpp`, `privacy.cpp` | token 발급기 계약과 텍스트 다시 쓰기. 발급기가 준 token을 다시 확인한다 | `TokenIssuer`(concept), `ProtectionTarget`, `protection_targets`, `apply_protection`, `protect` |
| `core/token.hpp`, `token.cpp` | 가명 token 형식 `⟦LABEL_R⟧`. 모양이 정확할 때만 token으로 본다 | `Token`, `token_label`, `parse_token`, `scan_tokens`, `TokenOccurrence` |
| `core/encoded.hpp`, `encoded.cpp` | 인코딩 덩어리 판정(대상 포함, 확인 불가 큰 덩어리) | `DecodeDepth`, `EncodedFinding`, `opaque_blob_min_bytes`, `judge_encoded` |
| `core/residual.hpp`, `residual.cpp` | 보호 후 남은 대상 검사 | `ResidualReport`, `verify_residual` |
| `core/provider_boundary.hpp`, `provider_boundary.cpp` | 외부로 보낼 요청을 검증된 질문만으로 새로 만든다 | `ProviderMessage`, `ProviderRequest`, `make_provider_request` |
| `core/link_context.hpp`, `link_context.cpp` | 응답 속 token이 링크·주소·HTML 태그 안에 있는지 판정 | `LinkContext`, `classify_link_contexts`, `check_link_contexts` |
| `core/restore.hpp`, `restore.cpp` | 응답 검사, 복원 계획, 복원 | `CheckedResponse`, `check_response`, `RestorePlan`, `plan_restore`, `TokenResolver`(concept), `plan_matches`, `splice_restored`, `apply_restore` |
| `core/reason.hpp`, `reason.cpp` | 거절 사유 코드와 사용자용·감사용 정보 분리 | `ReasonCode`, `reason_code_name`, `to_reason`, `Rejection`, `UserRejection`, `AuditRejection`, `AuditFinding` |
| `core/particle.hpp`, `particle.cpp` | 이름 구간 끝의 조사·호칭 떼기(NER용으로 준비) | `trim_trailing_particles` |
| `core/research.hpp`, `src/core/research/research_only.cpp` | 연구·시험 전용 열쇠. 운영 빌드에서는 만들 수 없다 | `ResearchOnly`, `make_research_only` |
| `core/version.hpp`, `version.cpp` | 프로젝트 버전과 Vault 프로토콜 버전 | `version`, `vault_protocol_version`, `vault_protocol_package` |
| `core/detail/state_key.hpp` | 단계 타입 생성 열쇠 | `StateKey<State>`, `StateAccess`(선언만) |
| `core/detail/attributes.hpp` | 반환한 view의 수명 경고 표시 | `PA_LIFETIMEBOUND` |
| `src/core/state_access.hpp` | 열쇠 공장. core 구현 안에만 있다 | `StateAccess::key` |
| `src/core/CMakeLists.txt` | `prompt_airlock_core`와 연구용 `prompt_airlock_core_research` 정의 | - |

헤더 경로는 `include/prompt_airlock/` 아래, 구현은 `src/` 아래다.

## detect

라이브러리 `prompt_airlock_detect`. core에만 의존하고 core와 같은 purity 검사를 받는다. 외부 라이브러리는 유니코드 정규화용 utf8proc 하나다.
탐지기는 위치와 종류만 내고, 막을지 바꿀지는 core가 정한다. 정규식 없이 한 번 훑는 방식이다.
처리 순서: 원문을 탐지용 보기로 바꾸고(UTF-8 검증, 폭 없는 문자 제거, NFKC 정규화), 규칙별로 찾은 뒤, 위치를 원문 byte로 되돌린다.

| 파일 | 하는 일 | 주요 타입·함수 |
|---|---|---|
| `detect/detectors.hpp`, `detectors.cpp` | 문서 단위 탐지 입구. 규칙들을 차례로 부르고 인코딩 덩어리를 깊이 2까지 풀어 다시 본다 | `Detectors::make`, `Detectors::detect`, `Detectors::detect_segment`, `DocumentDetection` |
| `detect/view.hpp`, `view.cpp` | 탐지용 보기. 정규화한 글자마다 원문 byte 구간을 기억한다 | `DetectionView`, `make_view`, `source_span` |
| `detect/scan.hpp`, `scan.cpp` | 숫자 묶음과 문장 경계 찾기 | `DigitGroup`, `DigitRun`, `digit_runs`, `SentenceSpan`, `sentences`, `max_digit_run` |
| `detect/terms.hpp`, `terms.cpp` | 단어 목록 일치기(Aho-Corasick: 여러 단어를 한 번에 찾는 알고리즘) | `TermMatcher::make`, `TermMatcher::find`, `TermHit` |
| `detect/encoded.hpp`, `encoded.cpp` | base64·hex·percent 등 인코딩 덩어리 찾기와 풀기 | `EncodedCandidate`, `encoded_candidates`, `decode`, `is_text`, `max_encoded_candidates` |
| `detect/sensitive.hpp` | 민감정보 범주와 통과 집계 | `SensitiveCategory`, `SensitiveTally` |
| `src/detect/rules.hpp` | 탐지기 내부 공통 타입(비공개) | `rules::Hit`, `for_each_window`, `Nearby`, `SensitiveMatchers`, 각 `find_*` 선언 |
| `src/detect/identifiers.cpp` | 전화, 주민·외국인등록, 사업자, 카드, 운전면허, 여권 번호 | `find_identifiers`, `is_phone_number`, `is_business_number` |
| `src/detect/accounts.cpp` | 계좌번호: 국내 형식표, IBAN과 외국 구조, 계좌 문맥 규칙 | `find_accounts` |
| `src/detect/network.cpp` | 이메일, IPv4, IPv6 | `find_network` |
| `src/detect/secrets.cpp` | 접두가 있는 키, JWT, Bearer 값, PEM 개인 키 | `find_secrets` |
| `src/detect/credentials.cpp` | 비밀번호 표지어 뒤 값, URL 사용자 정보, HTTP Basic, 계정 문맥 근처 무작위 문자열 | `find_credentials` |
| `src/detect/sensitive.cpp` | 범주어와 특정 개인 표지가 같은 창에 있으면 민감정보로 차단, 범주어만 있으면 집계 | `find_sensitive` |
| `src/detect/data/kr_identifier_formats.hpp` | 전화 대역, 여권 종류 문자, 운전면허 지역 | `area_codes`, `passport_type_letters`, `license_region_names` |
| `src/detect/data/kr_bank_account_formats.hpp` | 국내 금융기관 계좌번호 형식표 | `kr_account_formats` |
| `src/detect/data/iban_registry.hpp` | IBAN 국가별 구조(도구로 생성, 직접 고치지 않음) | `iban_countries` |
| `src/detect/data/foreign_account_formats.hpp` | IBAN 밖 외국 계좌 구조 | `anchored_formats`, `jp_pairs`, `aba_weights` |
| `src/detect/data/account_context_terms.hpp` | 계좌 문맥어와 통화 단위 | `account_context_terms`, `currency_after`, `currency_before` |
| `src/detect/data/credential_markers.hpp` | 비밀번호·사용자·계정 표지어 | `secret_markers`, `user_markers`, `account_markers` |
| `src/detect/data/secret_formats.hpp` | 키 접두, Bearer, JWT, PEM 머리 | `key_prefixes`, `jwt_head`, `pem_begin` |
| `src/detect/data/personal_markers.hpp` | 특정 개인 표지(호칭, 자기 진술) | `honorific_suffixes`, `self_statements` |
| `src/detect/data/sensitive_category_terms.hpp` | 민감정보 범주어 | `sensitive_terms` |
| `src/detect/CMakeLists.txt` | `prompt_airlock_detect` 정의 | - |

## vault_client

라이브러리 `prompt_airlock_vault_client`. core에만 의존한다. 외부 라이브러리는 protobuf(메시지 직렬화)와 Boost.Asio(비동기 I/O)다.
`proto/vault_v1.proto`에서 C++ 코드를 만드는 `prompt_airlock_vault_proto`도 같은 CMake 파일에서 정의한다.
Vault는 처음 범위를 열 때 자식 프로세스로 띄운다. 연결이 끊기고 Vault가 죽으면 그 세대(generation)의 범위는 모두 실패하고, 다음 `open_scope`가 새 비밀값으로 다시 띄운다.

| 파일 | 하는 일 | 주요 타입·함수 |
|---|---|---|
| `vault_client/types.hpp`, `types.cpp` | 공용 타입. 오류에는 코드만 담는다 | `ErrorCode`, `Error`, `Result<T>`, `fail`, `to_string`, `wipe`, `ScopeId`, `AuthSecret`, `TransportKind`, `Endpoint` |
| `vault_client/process.hpp`, `process.cpp` | Vault 실행과 종료. stdout의 READY 한 줄에서 주소·pid·비밀값을 읽는다. stdin을 닫으면 Vault가 끝난다 | `VaultProcess::spawn`, `VaultProcess::kill`, `close_stdin`, `wait_exit`, `SpawnOptions`, `ReadyInfo` |
| `vault_client/stream.hpp`, `stream.cpp` | Named Pipe·UDS 바이트 스트림. 모든 I/O에 timeout이 있고 서버 pid를 확인한다 | `ByteStream`, `open_stream`, `StreamOptions` |
| `vault_client/connection.hpp`, `connection.cpp` | 연결 하나. 인증 후 요청과 응답을 차례로 주고받는다. 한 번 실패하면 broken이 된다 | `VaultConnection::connect`, `VaultConnection::handshake`, `create_scope`, `create_token`, `resolve_exact`, `drop_scope`, `broken`, `ConnectionOptions` |
| `vault_client/service.hpp`, `service.cpp` | 프로세스 감독, 연결 풀, 재시작 간격, 요청 단위 범위. core 발급기·복원기 계약을 만족한다 | `VaultService::open_scope`, `vault_pid`, `VaultScope::issue`, `VaultScope::resolve`, `last_error`, `ServiceOptions`, `to_protection_error`, `to_restore_error` |
| `src/vault_client/CMakeLists.txt` | 생성 코드 라이브러리와 클라이언트 라이브러리 정의 | - |

## tls

라이브러리 `prompt_airlock_tls`. 서버(기관 앱 방향)와 클라이언트(provider 방향) TLS 설정을 하나씩 만든다. 협상 범위는 ADR 0014 로 고정이고 설정으로 바꿀 수 없다.

| 파일 | 하는 일 | 주요 타입·함수 |
|---|---|---|
| `tls/context.hpp`, `context.cpp` | TLS 1.2·1.3, AES-GCM, ECDHE(P-256·P-384), ECDSA·RSA-PSS 서명만 허용. 약한 인증서 키(RSA 2048 미만, 다른 곡선)는 기동 때 거절. 클라이언트는 상대 인증서를 항상 검증 | `make_server_context`, `make_client_context`, `TlsError` |

## gateway

라이브러리 `prompt_airlock_gateway`. HTTP 입구다(ADR 0020). 앞 단계에서 거절하면 본문을 읽지 않고 처리 단계(handler)도 부르지 않는다.

| 파일 | 하는 일 | 주요 타입·함수 |
|---|---|---|
| `gateway/config.hpp`, `config.cpp` | 설정 파일(JSON) 하나를 검증해 바꾸지 않는 값으로. 모르는 키·중복 키·잘못된 값이면 필드 경로와 함께 기동 거부 | `parse_config`, `Config`, `Origin`, `ConfigError` |
| `gateway/auth.hpp`, `auth.cpp` | Bearer token 의 SHA-256 을 등록 출처와 상수 시간 비교. 같은 주소에서 5번 이어 실패하면 60초 잠금 | `Authenticator`, `AuthFailure` |
| `gateway/error_body.hpp`, `error_body.cpp` | Chat Completions 호환 error 객체. 사유 코드 이름과 차단 종류만 담는다 | `error_response`, `EntryError`, `JsonResponse` |
| `gateway/server.hpp`, `server.cpp` | Beast HTTPS 서버(coroutine). TLS → 인증 → 경로·메서드·형식 → 등급 헤더 → 본문 상한 → handler 순서 | `Server`, `ServerLimits`, `AcceptedRequest`, `RequestHandler` |
| `gateway/request_json.hpp`, `request_json.cpp` | 요청 JSON 을 SAX 로 읽어 검사 대상 묶음과 파라미터로. 허용 밖 키·중복 키·깊이 16 초과에서 바로 멈춤 | `parse_request`, `ParsedRequest` |
| `gateway/provider_json.hpp`, `provider_json.cpp` | 검증된 요청으로 provider 요청 본문을 새로 만든다(고정 모델 별칭, n=1, stream=false) | `provider_request_body` |
| `gateway/pipeline.hpp`, `pipeline.cpp` | 처리 단계 연결. 어느 단계든 실패하면 provider 를 부르지 않는다 | `Pipeline`, `PseudonymScope`, `ScopeOpener`, `ProviderCall` |
| `src/gateway/role_name.hpp` | 메시지 역할 이름. 이전 응답 역할 이름은 바이트 배열 상수 한 곳에만 둔다(ADR 0020) | `detail::role_name`, `detail::parse_role` |
| `provider/https_client.hpp`, `src/provider/https_client.cpp` | 요청마다 검증된 TLS 연결, 응답 1 MiB·120초 상한, 자격 증명 파일 읽기 | `HttpsClient`, `load_credential` |

## Rust Vault

`vault/`는 Cargo workspace이고 crate는 `vault/crates/prompt-airlock-vault` 하나다.
token과 원문의 짝을 메모리에만 보관하는 별도 프로세스다. provider 자격 증명과 외부 네트워크 경로가 없다.
Gateway와는 Windows Named Pipe(현재 사용자만 허용) 또는 Linux UDS(파일 권한 0600)로만 통신한다. TCP는 없다.
`unsafe`는 workspace 설정으로 금지하고 `win_sec`과 `alloc` 두 모듈만 허용한다.

| 파일 | 하는 일 | 주요 타입·함수 |
|---|---|---|
| `vault/Cargo.toml`, `vault/Cargo.lock` | workspace 설정(판, 라이선스, lint)과 의존성 고정 | - |
| `crates/prompt-airlock-vault/Cargo.toml` | crate 설정. 의존성은 prost, tokio, zeroize, getrandom, windows-sys | - |
| `build.rs` | `proto/vault_v1.proto`에서 Rust 코드를 만든다. `PROTOC` 환경변수가 필요하다 | `main` |
| `src/lib.rs` | 모듈 목록과 프로토콜 상수 | `PROTOCOL_VERSION`, `PROTOCOL_PACKAGE`, `proto` |
| `src/main.rs` | 실행 파일. actor 시작, transport 열기, stdout에 READY 한 줄 출력, stdin이 닫히면 종료 | `main`, `parse_args`, `ALLOC` |
| `src/server.rs` | 연결 하나 처리. 첫 frame은 인증(hello)이어야 하고, 위반이면 오류 후 연결을 닫는다 | `ServerContext`, `serve_connection` |
| `src/transport.rs` | Named Pipe와 UDS 서버. 접근 제어만 다르고 같은 `serve_connection`을 쓴다 | `pipe::create`, `pipe::run`, `uds::bind`, `uds::run`, `uds::SocketGuard` |
| `src/codec.rs` | 길이 접두 frame 읽기·쓰기. 인코딩 뒤 원문 필드를 지운다 | `read_frame`, `write_frame`, `encode_response`, `encode_request`, `decode_wiping`, `FrameError` |
| `src/actor.rs` | 전용 스레드 하나가 상태를 소유하고, 나머지는 크기 제한 채널로 명령만 보낸다. 큐가 차면 즉시 Overloaded | `spawn`, `VaultHandle`, `Command`, `Pending`, `ActorJoin` |
| `src/state.rs` | 범위별 token과 원문 짝. 같은 값은 같은 token, 정확한 token만 복원, 만료 범위 정리 | `VaultState`, `create_scope`, `create_token`, `resolve_exact`, `drop_scope`, `sweep`, `Stats` |
| `src/token.rs` | token 생성과 모양 검사. 무작위 부분에 원문 4자가 나오면 다시 뽑는다 | `Token`, `generate`, `check_shape`, `random_part_leaks`, `ALPHABET` |
| `src/types.rs` | 도메인 타입. 원문은 `SecretValue`로만 다루고 drop 때 지운다 | `ScopeId`, `EntityLabel`, `SecretValue`, `AuthSecret`, `csprng_fill` |
| `src/config.rs` | 자원 한도와 timeout | `VaultLimits`, `ActorConfig`, `ServerConfig` |
| `src/error.rs` | 오류 값(원문·token·scope id 없음)과 proto 코드 변환 | `VaultError`, `VaultError::to_proto` |
| `src/clock.rs` | 단조 시계. 시험은 수동 시계로 만료를 확인한다 | `Clock`, `SystemClock`, `ManualClock` |
| `src/alloc.rs` | 해제되는 메모리를 0으로 지우는 전역 할당기 | `WipingAllocator` |
| `src/win_sec.rs` | Windows 보안 설명자. 현재 사용자 SID만 허용하는 파이프 생성 | `current_user_sid`, `create_pipe_current_user`, `pipe_security_sddl` |

## 통신 형식

`proto/vault_v1.proto`가 Gateway와 Vault의 유일한 메시지 정의다. C++와 Rust가 이 파일에서 각자 코드를 만든다.
전송 단위는 `[4바이트 big-endian 길이][protobuf 바이트]`이고, 기본 최대 크기는 65536바이트다.
모든 `Request`는 `protocol_version`과 `request_id`를 담고, 응답은 같은 `request_id`를 돌려준다.

| 연산 | 하는 일 |
|---|---|
| `Hello` | 연결의 첫 요청. Vault가 실행마다 만든 32바이트 비밀값으로 인증한다 |
| `CreateScope` | 요청 하나의 범위를 만든다. 16바이트 무작위 `scope_id`와 TTL(남는 시간 상한)을 돌려준다 |
| `CreateToken` | 범위, 라벨, 원문을 받아 token을 돌려준다 |
| `ResolveExact` | 정확히 같은 token일 때만 라벨과 원문을 돌려준다 |
| `DropScope` | 범위와 그 안의 짝을 모두 지운다 |
| `Error` | 실패 응답. `ErrorCode` 코드만 담는다 |

v1은 동결돼 있다. 바꾸려면 v2 package를 새로 만든다.

## 빌드와 도구

| 파일 | 하는 일 |
|---|---|
| `CMakeLists.txt` | 최상위 빌드. C++23, 세 라이브러리와 시험 폴더를 더한다. `PA_FUZZ`면 fuzz, `PA_WITH_VAULT`면 Vault와 e2e를 더한다 |
| `CMakePresets.json` | 빌드 preset: `win-debug`, `win-release`, `win-asan`, `linux-gcc14`, `linux-clang-asan-ubsan`, `linux-clang-tsan`, `linux-clang-fuzz` |
| `vcpkg.json` | C++ 의존성 고정: boost-asio, gtest, protobuf, utf8proc |
| `cmake/PromptAirlockOptions.cmake` | 공용 경고·sanitizer 옵션(`pa_options`), `PA_SANITIZE`, `PA_FUZZ`, `PA_WITH_VAULT` |
| `cmake/Vault.cmake` | cargo로 Rust Vault를 빌드·시험한다(`--locked`). vcpkg의 protoc를 넘긴다 |
| `cmake/CheckCorePurity.cmake` | core·detect 소스에서 금지 include와 호출을 찾는 검사 스크립트 |
| `cmake/CompileFail.cmake` | 빌드되면 안 되는 코드를 시험으로 등록하는 함수 `pa_add_compile_fail` |
| `cmake/RuntimeDlls.cmake` | 실행 파일 옆에 런타임 DLL을 복사하는 함수 `pa_copy_runtime_dlls` |
| `tools/win-dev.cmd` | MSVC 환경과 vcpkg 경로를 잡고 명령을 실행한다 |
| `tools/wsl-dev.sh` | WSL에서 vcpkg 경로를 잡고 명령을 실행한다 |
| `tools/gen-iban-table.mjs` | IBAN Registry 텍스트에서 `iban_registry.hpp`를 만든다 |
| `.github/workflows/build.yml` | PR과 main push에서 `linux-gcc14` workflow preset으로 빌드·시험 |
| `.github/workflows/publication-request.yml` | push·태그·릴리스 등 이벤트를 받아 공개 텍스트 검사를 요청한다(권한 없음) |
| `.github/workflows/publication-policy.yml` | 공개 텍스트 검사를 실행하고 PR에 `publication-policy` status를 남긴다 |
| `.github/scripts/publication-policy.mjs` | 금지 패턴 검사 모듈 `createPolicy` |
| `.github/scripts/run-publication-policy.mjs` | GitHub API로 커밋·PR·이슈를 모아 검사한다 |
| `.github/scripts/publication-policy.test.mjs` | 위 두 스크립트의 시험 |
| `.github/rulesets/` | 브랜치·태그·main 보호 규칙 JSON과 활성화 순서 안내 |
| `.github/ISSUE_TEMPLATE/`, `.github/pull_request_template.md` | 이슈 7종과 PR 본문 양식 |
| `.githooks/commit-msg`, `.githooks/pre-push`, `.githooks/publication-check.mjs` | 커밋·push 전에 CI와 같은 공개 텍스트 검사를 로컬에서 돌린다 |

## 시험

C++ 시험은 GoogleTest를 쓰고 ctest로 돈다. 시험 값은 모두 합성 값이다.

| 폴더 | 하는 일 | 파일 |
|---|---|---|
| `tests/unit/` | 파일 하나에 실행 파일 하나인 단위 시험 | core: `core_*_test.cpp` 21개(document, encoded, entity, grade, link_context, merge, offset, particle, pipeline, policy, privacy, prompt, reason, request_params, restore, sensitive, strategy, token, types, utf8, version). detect: `detect_*_test.cpp` 10개(accounts, credentials, encoded, evasion, formats, kr_accounts, pipeline, scan, sensitive, view). vault_client: `vault_client_mapping_test.cpp`(오류 대응표) |
| `tests/property/` | 고정 seed로 무작위 입력을 많이 넣어 성질을 확인한다 | `core_merge_property_test.cpp`, `core_protection_property_test.cpp`, `core_utf8_property_test.cpp` |
| `tests/compile_fail/` | 잘못 쓰면 빌드가 실패하는지 확인한다(위치 타입 섞기, 원문 복사, 단계 건너뛰기, 열쇠 위조, 연구용 열쇠 등). 파일마다 정상 짝이 함께 있다 | 16개 `.cpp` |
| `tests/purity/` | core와 detect에 금지 include가 없는지, 검사기가 위반을 실제로 잡는지 본다 | `CMakeLists.txt`, `violation/io_in_core.cpp`(일부러 만든 위반 입력) |
| `tests/fuzz/` | libFuzzer로 아무 바이트나 넣어 죽지 않고 불변식을 지키는지 본다. `linux-clang-fuzz` preset에서만 빌드한다. `corpus/`에 대상별 시작 입력이 있고, 바이너리 입력이 필요한 대상은 텍스트 사전(`<이름>.dict`)을 쓴다 | 아래 표 |
| `tests/e2e/` | 실제 Vault 프로세스로 하는 시험. `PA_WITH_VAULT=ON`일 때만 빌드한다 | `vault_client_test.cpp`(발급·정확 복원, 범위 격리, 인증 실패, 강제 종료 뒤 재시작, 여러 스레드 공유), `vault_pipeline_test.cpp`(요청 하나의 전체 흐름) |
| `tests/measure/` | 측정 도구. 기본 빌드와 ctest에 넣지 않고 직접 실행한다 | `detect_measure.cpp`(탐지 측정), `vault_measure.cpp`(Vault 발급·복원 지연) |
| `tests/support/` | 시험 전용 도구. 운영 타깃은 링크하지 않는다 | `fake_vault.hpp`(`FakeVault`, 가짜 발급기·복원기), `prng.hpp`(`SplitMix64`, `property_config`) |
| `vault/crates/prompt-airlock-vault/tests/` | Rust 통합 시험. 단위 시험은 각 `src/*.rs` 안의 `mod tests`에 있다 | `entry_point.rs`(READY 형식, stdin 종료, TCP 거절), `transport.rs`(접근 제어, 왕복), `zeroize_on_drop.rs`, `wiping_allocator.rs`(메모리 지움 확인), `allocator_cost.rs`(할당기 비용 측정, 직접 실행), `common/mod.rs`(시험용 클라이언트) |

fuzz 대상

| 대상 | 확인하는 것 |
|---|---|
| `fuzz_utf8` | UTF-8 검증·디코드·위치 변환이 서로 맞는다 |
| `fuzz_merge` | 합친 결과가 정렬되고 겹치지 않으며 입력을 모두 덮는다 |
| `fuzz_token` | 찾은 token이 모두 정확한 모양이고 겹치지 않는다 |
| `fuzz_link_context` | 링크 문맥 판정이 결정적이고 선형 시간에 끝난다 |
| `fuzz_detect` | 탐지 위치가 원문 글자 경계 안에 있고 두 번 돌려도 같다 |
| `fuzz_encoded` | 인코딩 후보가 원문 안에 있고 텍스트 판정이 엄격 UTF-8과 맞는다 |
| `fuzz_vault_frame` | 가짜 연결이 아무 바이트나 Vault 응답으로 돌려줘도 클라이언트가 죽지 않는다(`VaultConnection::handshake` 사용) |

## 아직 없는 것

| 항목 | 상태 |
|---|---|
| 응답 검사와 복원의 HTTP 연결, 실행 파일(`apps/prompt-airlock/`) | Phase 8a 다음 단위 |
| 감사 기록(`src/audit/`) | Phase 8. 지금은 `Rejection::for_audit`와 `SensitiveTally`가 기록할 값만 만든다 |
| 추론 worker와 동시성 제한 | Phase 9 |
| 실제 provider 연결 | Phase 10. 지금은 mock provider 로만 시험한다 |
| 연구 평가 | Phase 11. 지금은 `ResearchOnly` 열쇠와 연구용 전략만 있다 |
