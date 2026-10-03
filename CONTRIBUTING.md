# Contribution workflow

## 브랜치와 커밋

- 기본 브랜치는 `main`입니다. 초기 커밋 이후 변경은 작업 브랜치와 PR을 거칩니다.
- 브랜치는 `feature/<topic>`, `fix/<topic>`, `docs/<topic>`, `chore/<topic>`, `spike/<topic>` 형태를 사용합니다. topic은 소문자·숫자·하이픈으로 작성합니다.
- `develop`은 사용하지 않습니다. 작업 브랜치는 `main`에서 분기하여 PR로 `main`에 병합합니다.
- 커밋 제목은 `<type>: <change>` 형태를 사용합니다. 예: `docs: update contribution guide`.
- 이름과 설명은 변경 목적과 내용으로 작성합니다. 불필요한 작성 도구나 작성 과정 표기를 포함하지 않습니다.
- 작성자 정보는 실제 기여자만 나타내며, 자동 생성한 공동 작성자 trailer를 붙이지 않습니다.
- 승인 없이 force push, tag 생성, release 발행을 하지 않습니다.

## Pull request

- 하나의 PR은 하나의 검토 가능한 목적을 다룹니다.
- 문제, 변경 결과, 실제 검증 결과, 실패·미확인 사항을 기록합니다.
- 승인된 작업 범위를 지키고, 실행하지 않은 검증을 통과했다고 쓰지 않습니다.
- 미해결 review 대화를 해소한 뒤 squash merge합니다.
- 병합 후 작업 브랜치는 자동 삭제합니다.

`main`에는 PR 요구, 선형 이력, review 대화 해결 요구를 적용하며 force push와 삭제를 금지합니다. 관리자에게도 같은 규칙을 적용합니다.

초기 1인 운영 단계에서는 필수 reviewer 승인 수를 0으로 둡니다. 공개 자료 검사는 `publication-policy` status로 필수화합니다. 제품 build/test CI는 실제 job을 검증한 뒤 추가합니다. 협업자가 참여하면 필수 승인 수와 code ownership을 재검토합니다.

## 공개 자료 검사

커밋·작성자·브랜치·태그·PR·댓글·리뷰·이슈·릴리스·저장소 설명·공개 텍스트 파일을 검사합니다. 금지 패턴은 저장소에 포함하지 않고 `PUBLICATION_DENY_PATTERN` repository secret으로 관리합니다. 설정이 없거나 API 응답·검사가 불완전하면 실패합니다. 실패 로그에는 원문을 출력하지 않습니다.

PR 검사는 기본 브랜치의 검증 코드를 사용하고 PR head에 `publication-policy` status를 기록합니다. PR 코드를 실행하지 않으며, push 검사의 요청 workflow에는 secret이나 쓰기 권한을 주지 않습니다.

CI는 공개 후 실행됩니다. PR 병합은 required status로 차단할 수 있지만, GitHub에서 텍스트가 최초로 게시되는 모든 경로를 사전에 차단하지는 못합니다. 이벤트 검사 외에 매시간 전체 검사를 실행합니다. binary 파일·submodule·대용량 파일은 별도 정책이 마련되기 전까지 실패 처리합니다.

로컬 확인: `node --test .github/scripts/publication-policy.test.mjs`. ruleset JSON과 활성화 순서는 [.github/rulesets/README.md](.github/rulesets/README.md)를 참고합니다.

## 공개 범위와 라이선스

- 공개가 승인된 자료만 포함합니다. 로컬 설계·작업 문서와 참고자료는 기존 제외 정책을 유지합니다.
- 비밀값, 원문 개인정보, 민감한 원본 응답을 코드·fixture·로그·PR에 포함하지 않습니다.
- 테스트에는 합성 데이터를 사용합니다.
- 프로젝트 라이선스는 `AGPL-3.0-only`입니다.
- 외부 코드·dependency·모델·dataset은 추가 전에 license, provenance, 배포·NOTICE 조건을 검토합니다.
