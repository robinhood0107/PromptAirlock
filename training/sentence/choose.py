# 7.8-2 모델 고르기(#184 6절, 측정 전 고정). 사용: python choose.py <stage 폴더> [--out 결과.json]
# <stage 폴더>/<데이터 조건>/<바탕>.json(finetune.py --real-rules 결과)을 (바탕, 데이터, alpha) 마다 seed 평균·표준편차로 모으고,
# dev 만 보고 고른다: dev3 고르는 쪽 정상 경고 <= 3.0 이고 실제 dev 정상 경고 <= 3.0 인 구성 가운데
# (dev3 고르는 쪽 돌려 말함 재현율 + 실제 dev 재현율) / 2 가 가장 큰 것, 1%p 안에서 비기면 파라미터가 적은 바탕.
# 판정 셋 수치는 고른 뒤 모든 구성을 함께 표로 낸다.
import argparse
import json
from pathlib import Path

import numpy as np
import torch
from transformers import AutoConfig, AutoModelForSequenceClassification

from common import NONE
from finetune import BASES, HF

WARN_MAX = 3.0
TIE = 1.0
AXES = ["name", "title", "kin", "ending", "person_add", "topic_add", "mix"]


def params(base):
    # 학습한 구조(분류 머리 포함)를 meta 장치에 만들어 센다. 가중치는 불러오지 않는다.
    config = AutoConfig.from_pretrained(HF / BASES[base]["dir"], num_labels=NONE + 1)
    with torch.device("meta"):
        return sum(p.numel() for p in AutoModelForSequenceClassification.from_config(config).parameters())


def metrics(run):
    s, t, r = run["select"], run["test"], run["real"]
    m = {"sel_evasive": s["evasive"]["pct"], "sel_warn": s["benign_warn"]["pct"],
         "dev_recall": r["dev"]["recall"]["pct"], "dev_warn": r["dev"]["benign_warn"]["pct"],
         "test_evasive": t["evasive"]["pct"], "test_evasive_low": t["evasive"]["low"],
         "test_cat_low_min": min(v["low"] for v in t["evasive_by_category"].values()),
         "test_warn": t["benign_warn"]["pct"], "test_warn_high": t["benign_warn"]["high"],
         "real_recall": r["test"]["recall"]["pct"], "real_cat_right": r["test"]["category_right"]["pct"],
         "real_warn": r["test"]["benign_warn"]["pct"], "real_warn_high": r["test"]["benign_warn"]["high"],
         "tgt_recall": r["test-targeted"]["recall"]["pct"], "tgt_warn": r["test-targeted"]["benign_warn"]["pct"],
         "passed": float(run["verdict"]["all"])}
    m.update({f"axis_{a}": t["axes"][a]["pct"] for a in AXES})
    m.update({f"cat_{c}": v["pct"] for c, v in r["test+targeted"]["by_category"].items()})
    m["score"] = (m["sel_evasive"] + m["dev_recall"]) / 2
    return m


def configs(stage):
    for f in sorted(Path(stage).glob("*/*.json")):
        rec = json.loads(f.read_text(encoding="utf-8"))
        for alpha in sorted({r["alpha"] for r in rec["runs"]}):
            rs = [metrics(r) for r in rec["runs"] if r["alpha"] == alpha]
            yield dict(base=rec["base"], data=f.parent.name, alpha=alpha, clean=rec["clean"], seeds=len(rs),
                       mean={k: float(np.mean([x[k] for x in rs])) for k in rs[0]},
                       sd={k: float(np.std([x[k] for x in rs], ddof=1)) if len(rs) > 1 else 0.0 for k in rs[0]})


def choose(rows, n_params):
    ok = [r for r in rows if r["mean"]["sel_warn"] <= WARN_MAX and r["mean"]["dev_warn"] <= WARN_MAX]
    if not ok:
        return None, ok
    top = max(r["mean"]["score"] for r in ok)
    near = [r for r in ok if top - r["mean"]["score"] <= TIE]
    return min(near, key=lambda r: (n_params[r["base"]], -r["mean"]["score"])), ok


def differs(a, b, key):
    # 차이 판단: 평균 차가 두 구성 중 큰 표준편차의 2배를 넘을 때만.
    return abs(a["mean"][key] - b["mean"][key]) > 2 * max(a["sd"][key], b["sd"][key])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stage")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    rows = list(configs(a.stage))
    n_params = {b: params(b) for b in {r["base"] for r in rows}}
    pick, ok = choose(rows, n_params)
    f = lambda r, k: f"{r['mean'][k]:.1f}±{r['sd'][k]:.1f}"
    print(f"구성 {len(rows)}개, 정상 경고 조건 통과 {len(ok)}개")
    print("\n고르기 표(dev 만, 점수 순)\n")
    print("| 바탕 | 파라미터(백만) | 데이터 | alpha | seed | dev3 고르는 쪽 재현율 | dev3 고르는 쪽 정상 경고 | 실제 dev 재현율 | 실제 dev 정상 경고 | 점수 | 조건 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in sorted(rows, key=lambda r: -r["mean"]["score"]):
        print(f"| {r['base']} | {n_params[r['base']] / 1e6:.0f} | {r['data']} | {r['alpha']:g} | {r['seeds']} | {f(r, 'sel_evasive')} | {f(r, 'sel_warn')} | "
              f"{f(r, 'dev_recall')} | {f(r, 'dev_warn')} | {f(r, 'score')} | {'통과' if r in ok else '-'} |")
    print("\n판정 셋 표(고른 뒤 모든 구성, 점수 순)\n")
    print("| 바탕 | 데이터 | alpha | dev3 재는 쪽 재현율 | 하한 | 범주 하한 최소 | 정상 경고 | 상한 | 실제 test 재현율 | 범주 맞음 | 정상 경고 | 상한 | 드문 범주 재현율 | 낱말 든 정상 경고 | "
          + " | ".join(AXES) + " | 참고 판정 통과 seed |")
    print("|" + "---|" * (19 + len(AXES)))
    for r in sorted(rows, key=lambda r: -r["mean"]["score"]):
        print(f"| {r['base']} | {r['data']} | {r['alpha']:g} | {f(r, 'test_evasive')} | {r['mean']['test_evasive_low']:.1f} | {r['mean']['test_cat_low_min']:.1f} | "
              f"{f(r, 'test_warn')} | {r['mean']['test_warn_high']:.1f} | {f(r, 'real_recall')} | {r['mean']['real_cat_right']:.1f} | {f(r, 'real_warn')} | "
              f"{r['mean']['real_warn_high']:.1f} | {f(r, 'tgt_recall')} | {f(r, 'tgt_warn')} | "
              + " | ".join(f"{r['mean'][f'axis_{x}']:.1f}" for x in AXES) + f" | {r['mean']['passed'] * r['seeds']:.0f}/{r['seeds']} |")
    if pick:
        cats = sorted(k[4:] for k in pick["mean"] if k.startswith("cat_"))
        print(f"\n고른 구성: {pick['base']} / {pick['data']} / alpha {pick['alpha']:g} (점수 {f(pick, 'score')})")
        print("\n고른 구성의 실제 test+드문 범주 범주별 재현율\n")
        print("| " + " | ".join(cats) + " |\n|" + "---|" * len(cats))
        print("| " + " | ".join(f(pick, f"cat_{c}") for c in cats) + " |")
        print("\n고른 구성과 다른 구성의 점수 차이(평균 차 > 2 x 큰 sd)\n")
        for r in sorted(ok, key=lambda r: -r["mean"]["score"]):
            if r is not pick:
                print(f"- {r['base']} / {r['data']} / {r['alpha']:g}: {r['mean']['score'] - pick['mean']['score']:+.1f} {'차이 있음' if differs(r, pick, 'score') else '차이 없음'}")
    print("\n데이터 조건 효과(같은 바탕·alpha 안, 점수와 실제 test 재현율)\n")
    for b in sorted({r["base"] for r in rows}):
        for al in sorted({r["alpha"] for r in rows}):
            g = {r["data"]: r for r in rows if r["base"] == b and r["alpha"] == al}
            for x, y in (("S", "R"), ("S", "SR"), ("R", "SR")):
                if x in g and y in g:
                    print(f"- {b} a{al:g} {x}->{y}: 점수 {g[y]['mean']['score'] - g[x]['mean']['score']:+.1f}({'차이 있음' if differs(g[x], g[y], 'score') else '차이 없음'}), "
                          f"실제 test 재현율 {g[y]['mean']['real_recall'] - g[x]['mean']['real_recall']:+.1f}({'차이 있음' if differs(g[x], g[y], 'real_recall') else '차이 없음'}), "
                          f"주제어 붙이기 {g[y]['mean']['axis_topic_add'] - g[x]['mean']['axis_topic_add']:+.1f}")
    if a.out:
        Path(a.out).write_text(json.dumps(dict(params=n_params, rows=rows, pick=pick and {k: pick[k] for k in ("base", "data", "alpha")}),
                                          ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
