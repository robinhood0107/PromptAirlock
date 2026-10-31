# 시스템 세대 비교(결정 #182): 같은 셋·같은 평가로 규칙만(7.5 이전), 7.5 판별기, 7.6 선형 분류기, 합성 미세조정을 나란히 잰다.
# 사용: python compare.py --rules <rules-dev3-v2.jsonl> --out <결과.json> [--frozen <frozen json 폴더>] [--finetune <stage 폴더>...]
# 규칙만과 7.5 판별기는 여기서 직접 계산하고, 7.6 과 미세조정은 이미 낸 결과 JSON 의 재는 쪽 수치를 그대로 모은다.
import argparse
import json
from pathlib import Path

import numpy as np

from common import CATEGORIES, NONE, Dev3, Scorer, evaluate, verdict
from frozen_head import embeddings

CAND = json.loads((Path(__file__).resolve().parents[2] / "tests/fixtures/sentence/candidates.json").read_text(encoding="utf-8"))


def rules_only(dev, gate):
    probs = {t: np.zeros(NONE + 1) for t in dev.texts(False)}  # 판별기가 아무 것도 내지 않음
    sc = Scorer(probs, False, {c: 1e9 for c in CATEGORIES}, gate=gate)
    return {h: evaluate(dev, sc, h) for h in ("test", "select")}


def phase75(dev, gate, cache):
    # 7.5 판정 구성(ADR 0022): e5-small, 문장 나눔, 개인 조건, 범주별 예시 상위 3개 유사도 평균 - 정상 예시 최대 유사도, 문턱값 0.0128.
    texts = dev.texts(False)
    ex = {c: CAND["categories"][c]["examples"] for c in CATEGORIES}
    vec, _, _ = embeddings("e5", sorted(set(texts) | {e for v in ex.values() for e in v} | set(CAND["negatives"])), cache)
    neg = np.stack([vec[n] for n in CAND["negatives"]])
    exv = {c: np.stack([vec[e] for e in v]) for c, v in ex.items()}
    probs = {}
    for t in texts:
        v = vec[t]
        s = np.full(NONE + 1, -1e9)
        best_neg = float((neg @ v).max())
        for i, c in enumerate(CATEGORIES):
            sims = np.sort(exv[c] @ v)[::-1][:3]
            s[i] = float(sims.mean()) - best_neg
        probs[t] = s  # 확률이 아니라 점수지만 Scorer 는 최댓값과 문턱값만 쓴다
    sc = Scorer(probs, False, {c: 0.0128 for c in CATEGORIES}, gate=gate)
    return {h: evaluate(dev, sc, h) for h in ("test", "select")}


def summarize(m):
    return {"evasive": m["evasive"], "direct": m["direct"], "benign_flagged": m["benign_flagged"], "benign_warn": m["benign_warn"],
            "rule_false_block": m["rule_false_block"], "axes": m["axes"], "evasive_by_category": m["evasive_by_category"], "verdict": verdict(m)}


def from_results(folder, label):
    out = []
    for f in sorted(Path(folder).glob("*.json")):
        rec = json.loads(f.read_text(encoding="utf-8"))
        for alpha in sorted({r["alpha"] for r in rec["runs"]}):
            rs = [r for r in rec["runs"] if r["alpha"] == alpha]
            out.append({"system": label, "config": f"{rec.get('model') or rec.get('base')} {('l2=' + format(rec['l2'], 'g')) if 'l2' in rec else ''} alpha={alpha:g}{' mask' if rec.get('mask') else ''}",
                        "seeds": len(rs), "clean": rec["clean"],
                        "evasive_pct": [r["test"]["evasive"]["pct"] for r in rs], "evasive_low": [r["test"]["evasive"]["low"] for r in rs],
                        "benign_warn_pct": [r["test"]["benign_warn"]["pct"] for r in rs], "benign_warn_high": [r["test"]["benign_warn"]["high"] for r in rs],
                        "axes": {a: [r["test"]["axes"][a]["pct"] for r in rs] for a in rs[0]["test"]["axes"]},
                        "passed_seeds": sum(r["verdict"]["all"] for r in rs)})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--frozen", default="")
    ap.add_argument("--finetune", nargs="*", default=[])
    a = ap.parse_args()
    cache = Path(__file__).resolve().parents[1] / ".cache"
    dev = Dev3(a.rules)
    result = {"computed": {}, "collected": []}
    for gate in ("person", "person2"):
        result["computed"][f"rules_only/{gate}"] = {h: summarize(m) for h, m in rules_only(dev, gate).items()}
        result["computed"][f"phase75/{gate}"] = {h: summarize(m) for h, m in phase75(dev, gate, cache).items()}
    if a.frozen:
        result["collected"] += from_results(a.frozen, "phase76-frozen-linear")
    for folder in a.finetune:
        result["collected"] += from_results(folder, f"finetune-{Path(folder).name}")
    Path(a.out).write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    for k, v in result["computed"].items():
        m = v["test"]
        print(k, f"evasive {m['evasive']['pct']:.1f} (low {m['evasive']['low']:.1f}) direct {m['direct']['pct']:.1f} "
                 f"benign_flagged {m['benign_flagged']['pct']:.1f} warn {m['benign_warn']['pct']:.1f} "
                 + " ".join(f"{x} {y['pct']:.1f}" for x, y in m["axes"].items()))


if __name__ == "__main__":
    main()
