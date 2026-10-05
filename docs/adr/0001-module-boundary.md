# 0001. 모듈 경계

상태: 확정 (2026-10-05)

## 결정

Gateway는 C++ 프로세스 하나이며 다음 모듈로 나눈다.

| 모듈 | 책임 | I/O |
|---|---|---|
| core | 도메인 타입, prompt 상태 전이, 정책 평가, entity 병합, 가명 치환 계획, 잔여 검사 판정, token scan과 복원 판정, 조사 경계 처리 | 없음 |
| detect | 결정론 detector(정규식, checksum, secret, 기관 보호어), NER 결과 연결 | 없음 |
| ner | tokenizer, ONNX Runtime session, 크기가 정해진 추론 worker | 모델 파일, 추론 |
| vault_client | Vault 자식 프로세스 관리, IPC client | 프로세스, IPC |
| provider | 외부 LLM provider 호출 | 네트워크 |
| gateway | HTTP server, 요청 처리 순서 | 네트워크 |
| tls | TLS 설정 생성과 SHA-256, OpenSSL을 부르는 유일한 모듈([0014](0014-cryptography.md)) | 없음 |
| audit | 감사 메타데이터와 egress 이력(외부로 나간 그대로) 기록, 보존 기간 경과 시 삭제 | 로컬 파일 |

의존 방향은 I/O 모듈에서 core로만 향한다. core는 다른 모듈에 의존하지 않는다. provider는 검증이 끝난 prompt 타입만 받는다.

## 대안

- NER을 별도 프로세스로 분리: 장애 격리는 좋아지지만 IPC와 배포 단위가 늘어난다.
- 모듈을 나누지 않은 단일 라이브러리: 순수 판정과 I/O가 섞여 시험이 어려워진다.

## 근거

- 조사 경계 처리와 offset 역매핑을 순수 함수로 구현해 단위 시험으로 고정했다(Phase 2, 31개 시험).
- 응답 텍스트 복원을 core의 token scan과 Vault의 ResolveExact 조합으로 구성할 수 있음을 확인했다(Phase 3).

## 보안 영향

- 외부 전송 가능 여부를 타입으로 강제하는 지점이 core 하나에 모인다.
- ONNX Runtime 장애는 Gateway 프로세스를 함께 멈추게 한다. 요청은 거절되므로 원문이 나가지 않지만 가용성이 낮아진다.

## 변경 조건

- 추론 단계의 crash나 메모리 문제가 반복 관측되면 ner를 별도 프로세스로 분리한다.
