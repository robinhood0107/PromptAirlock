# Phase 2 spike — 한국어 NER / tokenizer / offset

최종 구조가 아닌 검증용 spike다. Python 없이 C++23 + ONNX Runtime 1.30.0(공식 배포본)으로
한국어 PERSON/ORG 탐지를 실행하고, 결과를 원문 UTF-8 바이트 offset 으로 돌려준다.

## 구성
- `src/text.*` — UTF-8 검증·디코드, 정규화(NFC, zero-width 제거, 비교용 NFKC). 정규화된 코드포인트마다 원문 바이트 구간을 함께 보관한다.
- `src/tokenizer.*` — `tokenizer.json` 을 읽는 native tokenizer. WordPiece(BERT/ELECTRA)와 Metaspace+BPE(byte fallback, Gemma 계열)만 지원하고, 그 밖의 구성은 로드 단계에서 거부한다. 사용자 텍스트의 special token 문자열은 special 로 해석하지 않는다.
- `src/model.*` — ORT 세션(CPU, intra/inter-op 1 thread). 512 토큰 초과 입력은 자르지 않고 거부한다.
- `src/decode.*` — BIO/BIOES label → 원문 바이트 span, 한국어 조사·호칭 후처리.
- `src/eval.*` — fixture 채점, 토큰별 offset 역검증.
- `tools/ner_bench.cpp` — 후보 하나를 한 프로세스에서 측정(정확도, offset, 지연, cold start, peak working set).
- `tools/tok_dump.cpp` + `oracle/` — 개발 전용 tokenizer oracle 비교(transformers.js 4.3.0). 런타임 경로에 포함되지 않는다.
- `fixtures/ner.jsonl` — 합성 fixture 60건(가상 인물·기관만 사용). `gen-fixtures.mjs` 로 생성한다.
- `fixtures/oracle/*.jsonl` — oracle 이 만든 기준 token id.

## 준비
모델 파일은 저장소에 넣지 않는다. 저장소 루트의 `models/phase-2/` 에 고정 커밋으로 받는다
(목록·SHA-256 은 `.work/artifacts-phase-2.md`). ONNX Runtime 은 `_deps/onnxruntime-win-x64-1.30.0/` 을 쓴다.

## 고정 명령 (Windows, Git Bash)
```
tools/build.sh win-release        # configure + build + ctest (win-debug, win-asan 도 같다)
tools/oracle.sh win-release       # 개발 전용: native tokenizer 와 oracle 비교, fixtures/oracle 갱신
tools/bench-all.sh <출력 디렉터리> 200
build/win-release/ner_bench.exe <후보> <models/phase-2> fixtures/ner.jsonl dump <fixture-id>   # 토큰별 label 진단
```
cmd 에서는 `tools\win-dev.cmd cmake --workflow --preset win-release` 를 직접 쓴다.
모델 파일이 없으면 모델 의존 테스트는 skip 된다.
