#!/usr/bin/env bash
# 후보마다 별도 프로세스로 ner_bench 를 실행해 JSON 을 남긴다.
# 사용: tools/bench-all.sh <out_dir> [runs] [preset]
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$here/../.." && pwd)"
out="${1:?out dir}"; runs="${2:-200}"; preset="${3:-win-release}"
mkdir -p "$out"
bench="$here/build/$preset/ner_bench.exe"
for c in koelectra-small-pii koelectra-small-pii-int8 veil-ko-lite-int8 nym-mmbert-small-int8; do
  for norm in nfc nfkc; do
    "$bench" "$c" "$root/models/phase-2" "$here/fixtures/ner.jsonl" "$runs" "$norm" > "$out/bench-$c-$norm.json"
  done
done
