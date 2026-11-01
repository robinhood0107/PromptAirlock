# 제품 C++ 판별기(sentence_classifier_measure 출력)와 Python 의 일치 확인(Phase 7.8-3).
# 사용(저장소 루트):
#   python parity.py input <rules-dev3.jsonl> <real rules.jsonl> <입력.jsonl>        C++ 에 넣을 글을 쓴다
#   python parity.py check <rules-dev3.jsonl> <real rules.jsonl> <C++ 출력.jsonl> <저장한 모델 폴더> <classifier.json>
# check 는 (1) C++ 확률과 PyTorch float32 확률의 최대 차이, (2) 학습 평가와 같은 bfloat16 확률로 낸 판정과 C++ 판정이
# 다른 글 수, (3) C++ 확률로 다시 낸 평가 수치를 출력한다. 원문은 출력하지 않는다.
import json
import sys

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from common import CATEGORIES, Dev3, RealSet, Scorer, evaluate, evaluate_real, read_jsonl
from finetune import REAL, probabilities


@torch.no_grad()
def float32_probabilities(tok, model, texts, maxlen, batch=64):
    out = {}
    for i in range(0, len(texts), batch):
        chunk = texts[i:i + batch]
        enc = tok(chunk, padding=True, truncation=True, max_length=maxlen, return_tensors="pt").to("cuda")
        out.update(zip(chunk, torch.softmax(model(**enc).logits.float(), dim=-1).cpu().numpy()))
    return out


def records(dev, real):
    return list(dev.rules.values()) + [r["rule"] for rows in real.parts.values() for r in rows]


def main():
    mode, rules, real_rules = sys.argv[1], sys.argv[2], sys.argv[3]
    dev, real = Dev3(rules), RealSet(REAL, real_rules)
    if mode == "input":
        with open(sys.argv[4], "w", encoding="utf-8") as f:
            for r in records(dev, real):
                f.write(json.dumps({"text": r["text"]}, ensure_ascii=False) + "\n")
        return
    cpp = {r["sentence"]: np.array(r["probs"], dtype=np.float64) for r in read_jsonl(sys.argv[4])}
    meta = json.loads(open(sys.argv[6], encoding="utf-8").read())
    thresholds = dict(zip(meta["categories"], meta["thresholds"]))
    assert meta["categories"] == CATEGORIES
    texts = sorted(cpp)
    tok = AutoTokenizer.from_pretrained(sys.argv[5])
    model = AutoModelForSequenceClassification.from_pretrained(sys.argv[5], dtype=torch.float32).to("cuda").eval()
    f32 = float32_probabilities(tok, model, texts, meta["max_tokens"])
    bf16 = probabilities(tok, model, texts, meta["max_tokens"], "cuda")
    diff = np.array([np.abs(cpp[t] - f32[t]).max() for t in texts])
    diff16 = np.array([np.abs(cpp[t] - bf16[t]).max() for t in texts])
    print(f"sentences {len(texts)}")
    print(f"C++ vs float32: max {diff.max():.2e}, p99 {np.quantile(diff, 0.99):.2e}, over 1e-4 {(diff > 1e-4).sum()}")
    print(f"C++ vs bfloat16(학습 평가): max {diff16.max():.2e}, p99 {np.quantile(diff16, 0.99):.2e}")
    sc_cpp = Scorer(cpp, False, thresholds, gate="person2")
    sc_f32 = Scorer(f32, False, thresholds, gate="person2")
    sc_16 = Scorer(bf16, False, thresholds, gate="person2")
    recs = records(dev, real)
    for name, other in (("float32", sc_f32), ("bfloat16", sc_16)):
        differ = sum(sc_cpp.warn(r) != other.warn(r) for r in recs)
        print(f"warn judgement differs from {name}: {differ} / {len(recs)} texts")
    for name, sc in (("C++", sc_cpp), ("bfloat16", sc_16)):
        m, s = evaluate(dev, sc, "test"), evaluate(dev, sc, "select")
        rm = {k: evaluate_real(rows, sc) for k, rows in real.parts.items()}
        print(f"{name}: dev3 select evasive {s['evasive']['pct']:.1f} warn {s['benign_warn']['pct']:.1f} | test evasive {m['evasive']['pct']:.1f} "
              f"warn {m['benign_warn']['pct']:.1f} topic_add {m['axes']['topic_add']['pct']:.1f} | real dev recall {rm['dev']['recall']['pct']:.1f} "
              f"warn {rm['dev']['benign_warn']['pct']:.1f} | test recall {rm['test']['recall']['pct']:.1f} warn {rm['test']['benign_warn']['pct']:.1f} "
              f"| targeted recall {rm['test-targeted']['recall']['pct']:.1f} warn {rm['test-targeted']['benign_warn']['pct']:.1f}")


if __name__ == "__main__":
    main()
