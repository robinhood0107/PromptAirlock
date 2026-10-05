# 0011. 저장소 구조

상태: 확정 (2026-10-05). 시험 디렉터리를 2026-10-05에 더했다.

## 결정

```text
CMakeLists.txt, CMakePresets.json, vcpkg.json
cmake/                  빌드 옵션, sanitizer, 런타임 DLL 복사
include/prompt_airlock/ 공개 헤더
src/core/               도메인 타입, 상태 전이, 판정 함수
src/detect/             결정론 detector
src/ner/                tokenizer, 추론
src/vault_client/       Vault 프로세스 관리와 IPC client
src/provider/           외부 provider adapter
src/gateway/            HTTP server, 요청 처리
src/audit/              메타데이터 로컬 기록
src/tls/                TLS 설정, SHA-256
apps/prompt-airlock/    Gateway 실행 파일
vault/                  Rust workspace, crates/prompt-airlock-vault
proto/                  vault_v1.proto
tests/unit/, tests/integration/, tests/e2e/, tests/fuzz/
tests/compile_fail/     빌드되면 안 되는 코드와 그 정상 짝
tests/property/         고정 seed property 시험
tests/purity/           core 소스 금지 패턴 검사
tests/support/          시험 전용 도구(운영 타깃은 링크하지 않음)
fixtures/               합성 데이터
tools/                  개발 환경 wrapper
docs/adr/               결정 기록
spikes/                 사전 실험 코드, 제품 빌드에 포함하지 않음
```

- 모듈 디렉터리는 그 모듈의 첫 코드가 생길 때 만든다. 빈 자리표시 파일은 두지 않는다.
- C++와 Rust가 함께 쓰는 IPC 정의는 `proto/` 한 곳에만 둔다.
- 시험 데이터는 합성 데이터만 저장소에 넣는다. 모델 파일은 저장소에 넣지 않는다.

## 대안

- 언어별 최상위 디렉터리(`cpp/`, `rust/`).

## 근거

- 사전 실험 코드가 위 경계(판정 함수, NER, Vault client, Rust Vault, 공용 proto)로 나뉘었다.
- 모듈 경계는 [0001](0001-module-boundary.md)을 따른다.

## 변경 조건

- 모듈 경계가 바뀌면 함께 바꾼다.
