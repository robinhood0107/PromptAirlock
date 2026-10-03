# Repository rules

- `main.json`: PR, 필수 `publication-policy` status, 선형 이력, 대화 해결, force push·삭제 금지. 관리자 bypass 없음.
- `branches.json`: `main`과 `feature/*`, `fix/*`, `docs/*`, `chore/*`, `spike/*` 이외의 브랜치 생성 차단.
- `tags.json`: force update·삭제 금지. `vMAJOR.MINOR.PATCH` 형식은 CI에서 검사합니다.

이 저장소의 API가 이름 정규식 규칙을 거부하여, 브랜치 접두사는 creation restriction으로 제한합니다. 이름 전체와 비공개 금지 패턴은 CI에서 검사합니다.

## 활성화 순서

1. `PUBLICATION_DENY_PATTERN` repository secret을 설정합니다. 값은 로컬에서 검증한 JavaScript 정규식이며 저장소에 올리지 않습니다.
2. 검사 workflow와 스크립트를 `main`에 반영합니다. 기존 PR 보호는 유지합니다.
3. Actions에서 `Publication policy`를 수동 실행하여 전체 검사 성공을 확인합니다.
4. 테스트 PR에서 정상 입력 PASS, 금지 입력 FAIL, PR head SHA의 `publication-policy` status 기록을 확인합니다.
5. 아래 ruleset을 활성화합니다. 필수 status가 아직 생성되지 않은 상태에서 `main.json`을 먼저 활성화하지 않습니다.

```sh
gh api repos/robinhood0107/PromptAirlock/rulesets --method POST --input .github/rulesets/main.json
gh api repos/robinhood0107/PromptAirlock/rulesets --method POST --input .github/rulesets/branches.json
gh api repos/robinhood0107/PromptAirlock/rulesets --method POST --input .github/rulesets/tags.json
```

이미 같은 이름의 ruleset이 있으면 해당 ID의 `PUT` endpoint로 갱신합니다. import 시에도 각 JSON을 사용할 수 있습니다. 기존 branch protection과 ruleset은 함께 적용되며, 기존 보호를 삭제할 필요가 없습니다.

## 검사 한계

CI는 GitHub에 자료가 게시된 뒤 실행되므로 최초 공개를 되돌리거나 사전에 차단하지 못합니다. 금지 패턴에 없는 표현이나 이미지 내부의 텍스트까지 판별하지는 못합니다. binary 파일은 검사 성공으로 처리하지 않습니다.

이벤트에 PR head가 있으면 다른 API 조회 전에 기존 status를 pending으로 바꿉니다. 다만 저장소 전체 이벤트에서 GitHub API 장애로 대상 PR 조회나 status 갱신 자체가 불가능하면 이전 성공 status가 남을 수 있습니다. 이 경우 실패한 검사 실행을 확인하여 병합을 중단하고 재검사해야 합니다. 이 CI를 모든 공개 경로의 사전 차단이나 API 장애 중의 완전한 병합 통제로 간주하지 않습니다.

제품 build/test CI는 Phase 1 검증 이후 `main.json`의 required checks에 추가합니다. 지금은 존재하지 않는 job 이름을 필수화하지 않습니다.
