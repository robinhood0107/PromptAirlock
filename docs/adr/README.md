# Architecture Decision Records

본 구현 전에 동결한 결정이다. 각 문서는 결정, 대안, 근거, 보안 영향, 변경 조건을 적는다. 근거 수치는 `spikes/`의 실험 코드로 측정했다.

| 번호 | 제목 | 상태 |
|---|---|---|
| [0001](0001-module-boundary.md) | 모듈 경계 | 확정 |
| [0002](0002-language-and-process-boundary.md) | 언어와 프로세스 경계 | 확정 |
| [0003](0003-vault-ipc.md) | Vault IPC 스키마와 transport | 확정 |
| [0004](0004-http-stack.md) | HTTP stack | 확정 |
| [0005](0005-dependency-manager.md) | 의존성 관리 | 확정 |
| [0006](0006-korean-ner-and-tokenizer.md) | 한국어 NER과 tokenizer | 확정 |
| [0007](0007-canonical-offset.md) | 기준 offset과 정규화 | 확정 |
| [0008](0008-pseudonym-token-format.md) | 가명 token 형식 | 확정 |
| [0009](0009-runtime-libraries.md) | 런타임 DLL/SO 배치 | 확정 |
| [0010](0010-build-and-test-commands.md) | 빌드·테스트 명령 | 확정 |
| [0011](0011-repository-layout.md) | 저장소 구조 | 확정 |
| [0012](0012-deployment.md) | 배포와 운영 전제 | 확정 |
| [0013](0013-grade-identification.md) | 기관 분류 등급의 식별 | 확정 |
| [0014](0014-cryptography.md) | 암호 사용 범위와 알고리즘 | 확정 |
| [0015](0015-default-actions.md) | 판정 기본값 | 확정 |
| [0016](0016-detection-coverage.md) | 탐지 범위: 계좌번호, 인증 정보, 민감정보, 고유식별정보 | 확정 |
| [0017](0017-request-response-boundary.md) | 외부 요청·응답 경계: 허용 필드, 복원 위치, 인코딩 | 확정 |

결정을 바꿀 때는 해당 문서의 상태를 "대체됨"으로 바꾸고 새 번호로 문서를 추가한다.
