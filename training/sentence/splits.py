# 말뭉치 문장의 문서 단위 분할과 데이터셋별 표본 상한(Phase 7.8-1, 결정 #182).
# 사용: python splits.py <말뭉치 폴더(corpora)> [--cap 200000] [--seed 20261031]
# 1) 문서 단위 분할: sha256("<데이터셋>:<문서>") 로 train 80 / dev 10 / test 10. 같은 문서의 문장은 한 곳에만 들어가
#    문서 안 표현이 학습과 평가에 갈라 들어가지 않는다. test 는 판정용으로 봉인하고 학습·고르기에 쓰지 않는다.
# 2) 데이터셋별 상한: 한 데이터셋(예: SNS 1,942만 문장)이 학습 분포를 차지하지 않게, 나눈 몫마다 데이터셋별로
#    문서를 무작위(고정 seed) 순서로 돌며 상한까지 문장을 담는다. 원본 문장 파일은 그대로 두고 uid 목록만 쓴다.
# 출력: <말뭉치 폴더>/splits/<몫>/<데이터셋>.uids, splits/SPLITS.json(개수, 상한, seed, 각 파일 sha256)
import argparse
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path

SHARES = (("train", 80), ("dev", 10), ("test", 10))


def share_of(ds, doc):
    h = int(hashlib.sha256(f"{ds}:{doc}".encode("utf-8")).hexdigest(), 16) % 100
    edge = 0
    for name, pct in SHARES:
        edge += pct
        if h < edge:
            return name
    raise AssertionError


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--cap", type=int, default=200_000, help="몫·데이터셋마다 담을 문장 수 상한(dev·test 는 상한의 1/8)")
    ap.add_argument("--seed", type=int, default=20261031)
    a = ap.parse_args()
    root = Path(a.root)
    out = root / "splits"
    report = {"seed": a.seed, "cap": {"train": a.cap, "dev": a.cap // 8, "test": a.cap // 8}, "datasets": {}}
    for f in sorted((root / "sentences").glob("aihub-*.jsonl")):
        ds = f.stem.removeprefix("aihub-")
        docs = {name: defaultdict(list) for name, _ in SHARES}
        total = 0
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                docs[share_of(ds, r["doc"])][r["doc"]].append(r["uid"])
                total += 1
        entry = {"sentences": total}
        for name, _ in SHARES:
            cap = report["cap"][name]
            order = sorted(docs[name])
            random.Random(f"{a.seed}:{ds}:{name}").shuffle(order)
            picked = []
            for d in order:
                if len(picked) >= cap:
                    break
                picked.extend(docs[name][d][: cap - len(picked)])
            path = out / name / f"{ds}.uids"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(picked) + "\n", encoding="utf-8")
            entry[name] = {"docs": len(docs[name]), "sentences": sum(map(len, docs[name].values())), "picked": len(picked),
                           "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        report["datasets"][ds] = entry
        print(ds, json.dumps(entry, ensure_ascii=False), flush=True)
    (out / "SPLITS.json").write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
