# 봉인 판정과 실제 문서 그림자 운영 집계(Phase 7.9, #194). 판별기는 고정된 제품 파일(classifier.json)과 C++ 확률을 그대로 쓴다.
# 사용(저장소 루트):
#   python sealed_judge.py input <rules.jsonl> <C++ 입력.jsonl>
#       규칙 판정 파일(sentence_measure --rules-out ... --docs ... --lines ...)의 글을 C++ 측정 도구 입력({"text"})으로 쓴다.
#   python sealed_judge.py judge <정답 폴더> <rules.jsonl> <C++ 출력.jsonl> <classifier.json> <결과.json> [kappa.json]
#       정답 폴더의 random.jsonl(자연 분포)·targeted.jsonl(범주 표적)과 문서 문장("doc/<파일>#n")을 #194 4절 기준으로 판정한다.
# 원문은 출력하지 않는다. 결과 파일에는 개수·비율·구간만 들어간다.
import json
import sys
from collections import defaultdict
from pathlib import Path

from common import CATEGORIES, Scorer, evaluate_real, rate, read_jsonl, rule_block

# #194 4절(측정 전 고정): 하한·상한은 Wilson 95% 구간.
RECALL_LOW, CATEGORY_LOW, CATEGORY_MIN_N, WARN_HIGH, DOC_MIN_N, KAPPA_MIN = 70.0, 55.0, 60, 5.0, 800, 0.8


def judge(labels, rules_path, cpp_path, settings_path, out_path, kappa_path=None):
    rules = {r["key"]: r for r in read_jsonl(rules_path)}
    meta = json.loads(Path(settings_path).read_text(encoding="utf-8"))
    assert meta["categories"] == CATEGORIES
    probs = {r["sentence"]: r["probs"] for r in read_jsonl(cpp_path)}
    scorer = Scorer(probs, False, dict(zip(meta["categories"], meta["thresholds"])), gate="person2")
    parts = {}
    for name in ("random", "targeted"):
        rows = read_jsonl(Path(labels) / f"{name}.jsonl")
        for r in rows:
            r["rule"] = rules["line:" + r["id"]]
        parts[name] = rows
    every = parts["random"] + parts["targeted"]
    m = {name: evaluate_real(rows, scorer) for name, rows in parts.items()}
    m["all"] = evaluate_real(every, scorer)
    normal = [r for r in parts["random"] if not r["sensitive"]]
    m["rule_false_block_random"] = rate(sum(rule_block(r["rule"], False, None) for r in normal), len(normal))

    docs = [r for k, r in rules.items() if k.startswith("doc/")]
    by_doc = defaultdict(list)
    for r in docs:
        by_doc[r["key"][4:].split("__")[0]].append(r)
    warned = [scorer.warn(r) and not rule_block(r, False, None) for r in docs]
    m["docs"] = {
        "sentence_warn": rate(sum(warned), len(docs)),
        "sentence_rule_block": rate(sum(rule_block(r, False, None) for r in docs), len(docs)),
        "document_warn": rate(sum(any(scorer.warn(r) and not rule_block(r, False, None) for r in rs) for rs in by_doc.values()), len(by_doc)),
        "by_source": {src: rate(sum(scorer.warn(r) and not rule_block(r, False, None) for d, rs in by_doc.items() if d[0] == src for r in rs),
                                sum(len(rs) for d, rs in by_doc.items() if d[0] == src)) for src in sorted({d[0] for d in by_doc})},
    }
    cats = defaultdict(int)
    for r, w in zip(docs, warned):
        if w:
            cats[scorer.score(r)[1]] += 1
    m["docs"]["warned_categories"] = dict(sorted(cats.items(), key=lambda x: -x[1]))
    kappa = json.loads(Path(kappa_path).read_text(encoding="utf-8")) if kappa_path else None

    a = m["all"]
    checks = [
        ("민감 문장 재현율(규칙 또는 판별기) 하한", a["recall"]["low"], f">= {RECALL_LOW}", a["recall"]["low"] >= RECALL_LOW),
        ("정상 문장 경고율(무작위) 상한", m["random"]["benign_warn"]["high"], f"<= {WARN_HIGH}", m["random"]["benign_warn"]["high"] <= WARN_HIGH),
        ("실제 문서 문장 경고율 상한", m["docs"]["sentence_warn"]["high"], f"<= {WARN_HIGH} (n >= {DOC_MIN_N})",
         m["docs"]["sentence_warn"]["high"] <= WARN_HIGH and m["docs"]["sentence_warn"]["n"] >= DOC_MIN_N),
    ]
    for c in CATEGORIES:
        x = a["by_category"][c]
        if x["n"] >= CATEGORY_MIN_N:
            checks.append((f"범주 재현율 하한 {c}", x["low"], f">= {CATEGORY_LOW}", x["low"] >= CATEGORY_LOW))
    if kappa:
        checks.append(("정답 일치도 kappa", kappa["kappa"], f">= {KAPPA_MIN}", kappa["kappa"] >= KAPPA_MIN))
    m["checks"] = [{"item": i, "value": round(v, 2), "criterion": c, "pass": bool(p)} for i, v, c, p in checks]
    m["reference_categories"] = {c: a["by_category"][c] for c in CATEGORIES if a["by_category"][c]["n"] < CATEGORY_MIN_N}
    m["kappa"] = kappa
    m["pass"] = all(p for *_, p in checks)
    Path(out_path).write_text(json.dumps(m, ensure_ascii=False, indent=1), encoding="utf-8")
    for x in m["checks"]:
        print(f"{'PASS' if x['pass'] else 'FAIL'}  {x['item']}: {x['value']} ({x['criterion']})")
    for c, x in m["reference_categories"].items():
        print(f"참고  범주 {c}: {x['k']}/{x['n']} ({x['pct']:.1f}%)")
    print("overall", "PASS" if m["pass"] else "FAIL")


def main():
    if sys.argv[1] == "input":
        with open(sys.argv[3], "w", encoding="utf-8") as f:
            for r in read_jsonl(sys.argv[2]):
                f.write(json.dumps({"text": r["text"]}, ensure_ascii=False) + "\n")
        return
    judge(*sys.argv[2:8])


if __name__ == "__main__":
    main()
