#!/usr/bin/env bash
# 개발 전용: native tokenizer 출력과 transformers.js(oracle) 를 비교하고 fixtures/oracle/*.jsonl 을 갱신한다.
# oracle 의 node_modules 는 저장소 밖(%LOCALAPPDATA%\prompt-airlock\phase-2-oracle)에 설치한다.
# 사용: tools/oracle.sh [preset]   (먼저 tools/build.sh 로 tok_dump 를 빌드)
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$here/../.." && pwd)"
preset="${1:-win-release}"
models="$root/models/phase-2"
fixtures="$here/fixtures/ner.jsonl"
oracle_home="${LOCALAPPDATA:?}/prompt-airlock/phase-2-oracle"
mkdir -p "$oracle_home" "$here/fixtures/oracle"
cp "$here/oracle/package.json" "$here/oracle/package-lock.json" "$here/oracle/tokenize.mjs" "$oracle_home/"
(cd "$oracle_home" && npm ci --no-audit --no-fund >/dev/null)
dump="$here/build/$preset/tok_dump.exe"
tmp="$(mktemp -d)"
# 이름|tokenizer.json(모델 루트 기준)|transformers.js 가 읽을 디렉터리
for row in "atonlee|atonlee_koelectra-ko-pii-ner/tokenizer.json|atonlee_koelectra-ko-pii-ner" \
           "veil|1T_veil-pii-ko-lite/tokenizer.json|1T_veil-pii-ko-lite" \
           "nym|Wismut_nym-pii-multilingual-small/int8/tokenizer.json|Wismut_nym-pii-multilingual-small"; do
  IFS='|' read -r name tj dir <<<"$row"
  for mode in nfc raw; do
    "$dump" "$models/$tj" "$fixtures" "$mode" > "$tmp/$name-$mode.jsonl"
    node "$oracle_home/tokenize.mjs" "$models" "$dir" "$fixtures" "$tmp/$name-$mode.jsonl" \
      "$here/fixtures/oracle/$name-$mode.jsonl"
  done
done
rm -rf "$tmp"
