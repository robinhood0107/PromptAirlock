# 실험 결과 JSON(frozen_head.py, finetune.py)을 표로 모은다. 사용: python report.py <결과 폴더...> [--half test|select]
# 구성(파일·L2·alpha)마다 seed 평균과 흩어짐, 참고 판정을 통과한 seed 수를 낸다. 고르는 규칙은 측정 전에 정한 대로
# 이슈에 적은 것을 따르고, 이 스크립트는 숫자만 모은다.
import json
import sys
from pathlib import Path

import numpy as np

AXES = ["name", "title", "kin", "ending", "person_add", "topic_add", "mix"]


def rows(paths, half):
    for p in paths:
        for f in sorted(Path(p).rglob("*.json")):
            rec = json.loads(f.read_text(encoding="utf-8"))
            name = rec.get("model") or rec.get("base")
            tag = f"{name}{'-mask' if rec.get('mask') else ''}" + (f" l2={rec['l2']:g}" if "l2" in rec else f" lr={rec['lr']:g} ep={rec['epochs']}")
            for alpha in sorted({r["alpha"] for r in rec["runs"]}):
                rs = [r for r in rec["runs"] if r["alpha"] == alpha]
                m = [r[half] for r in rs]
                yield dict(tag=tag, clean=rec["clean"], alpha=alpha, seeds=len(rs),
                           evasive=np.mean([x["evasive"]["pct"] for x in m]), evasive_sd=np.std([x["evasive"]["pct"] for x in m]),
                           evasive_low=np.mean([x["evasive"]["low"] for x in m]),
                           cat_low_min=np.mean([min(v["low"] for v in x["evasive_by_category"].values()) for x in m]),
                           warn=np.mean([x["benign_warn"]["pct"] for x in m]), warn_high=np.mean([x["benign_warn"]["high"] for x in m]),
                           frames67=np.mean([x["evasive_frames_6_7"]["pct"] for x in m]),
                           frames05=np.mean([x["evasive_frames_0_5"]["pct"] for x in m]),
                           axes={a: np.mean([x["axes"][a]["pct"] for x in m]) for a in AXES},
                           passed=sum(r["verdict"]["all"] for r in rs) if half == "test" else None,
                           checks=np.mean([sum(v for k, v in r["verdict"].items() if k != "all") for r in rs]),
                           train_acc=np.mean([r["train_acc"] for r in rs]))


def main():
    half = "test"
    args = [a for a in sys.argv[1:]]
    if "--half" in args:
        half = args[args.index("--half") + 1]
        args = [a for i, a in enumerate(args) if a != "--half" and (i == 0 or args[i - 1] != "--half")]
    head = "| 구성 | 출처 | alpha | seed | 돌려 말함(평균±sd) | 하한 | 범주 하한 최소 | 정상 경고 | 상한 | 틀0-5 / 6-7 | " + " | ".join(AXES) + " | 학습셋 정확도 | 통과 seed |"
    print(head)
    print("|" + "---|" * (head.count("|") - 1))
    for r in sorted(rows(args, half), key=lambda x: (-x["evasive_low"])):
        print(f"| {r['tag']} | {'확인' if r['clean'] else '참고'} | {r['alpha']:g} | {r['seeds']} | {r['evasive']:.1f}±{r['evasive_sd']:.1f} | "
              f"{r['evasive_low']:.1f} | {r['cat_low_min']:.1f} | {r['warn']:.1f} | {r['warn_high']:.1f} | {r['frames05']:.1f} / {r['frames67']:.1f} | "
              + " | ".join(f"{r['axes'][a]:.1f}" for a in AXES)
              + f" | {100 * r['train_acc']:.1f} | {r['passed'] if r['passed'] is not None else '-'} |")


if __name__ == "__main__":
    main()
