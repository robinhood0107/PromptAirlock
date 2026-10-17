# token 보존율 측정 (Phase 4.5)

외부 LLM이 가명 token(`⟦PERSON_7Q2MK4XD9A⟧` 모양, ADR 0008)을 답에 그대로 돌려주는지 잰다. 제품 빌드에 포함하지 않는 측정 도구이며 Node 표준 라이브러리만 쓴다.

## 하는 일

- 합성 사례 40개(요약, 답장, 목록, 번역, 공문체 다시 쓰기)를 두 조건으로 보낸다.
  - `plain`: 안내 없이 질문만
  - `hint`: "표시를 글자 하나도 바꾸지 말고 옮겨 쓰라"는 시스템 안내를 붙여서
- 답에서 token마다 `exact`(그대로), `case`(대소문자), `bracket`(괄호), `spacing`(공백), `label`(라벨 변경), `missing`(없음)을 판정하고, 입력에 없던 token(지어낸 것)도 센다.
- `temperature`, `top_p`는 보내지 않는다. 출력 길이는 `max_completion_tokens`로 보낸다.

## 자격 증명과 설정

설정과 키는 저장소의 `secrets/` 폴더에 둔다. 이 폴더는 `.gitignore`로 추적에서 빠진다. 커밋·이슈·로그에 키를 남기지 않는다.

1. `config.example.json`을 `secrets/token-survival.json`으로 복사하고 `endpoint`, `model`을 채운다.
2. 인증을 고른다.
   - `{"type": "gcloud"}`: `gcloud auth application-default login`을 해 두면 도구가 access token을 받아 쓴다(45분마다 갱신). Vertex 기본값.
   - `{"type": "bearer-env", "env": "환경 변수 이름"}`: 키를 환경 변수로 준다.
   - `{"type": "bearer-file", "path": "secrets/키 파일"}`: 키를 파일로 준다.
3. 다른 Chat Completions 호환 서비스도 `endpoint`, `model`, `auth`만 바꾸면 같은 도구로 잰다.

## 실행

```bash
node spikes/token-survival/survival.mjs secrets/token-survival.json
```

결과는 `secrets/token-survival-out/<시각>.json`(사례별 답과 판정, 조건별 요약)에 남는다. 요약은 `[Measure]` 이슈로 올리되 서비스·모델 이름과 답 원문은 올리지 않는다.

## 도구 시험

```bash
node --test spikes/token-survival/survival.test.mjs
```

가짜 서버로 요청 주소, 인증 헤더, 본문 모양, 재시도, 판정, 요약을 확인한다. 실제 서비스와 키는 쓰지 않는다.

## 판정 기준(제안)

정확 보존 95% 이상이면 token 형식을 유지한다. 미만이면 형식 재검토 결정 이슈를 연다. 바뀐 token을 복원하지 않는다는 규칙은 결과와 상관없이 유지한다.
