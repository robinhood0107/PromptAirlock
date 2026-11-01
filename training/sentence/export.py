# 미세조정한 분류기를 ONNX 로 내보낸다(Phase 7.8-1, 결정 #174). 제품은 이 ONNX 를 C++ ONNX Runtime 으로 돌린다.
# 사용: training\.venv\Scripts\python training\sentence\export.py <저장한 모델 폴더> <내보낼 .onnx> [<finetune 결과 json> <seed> <alpha>]
# 결과 json 을 주면 C++ 판별기가 읽을 classifier.json(범주 순서, 문턱값, 최대 token, 개인 조건 v2 목록, 파일 해시)과
# tokenizer.json 을 .onnx 옆에 함께 쓴다(Phase 7.8-3).
# 입력 input_ids, attention_mask(길이 가변), 출력 logits [묶음, 12]. 내보낸 뒤 같은 문장들로 PyTorch 와 ONNX Runtime 의
# 확률 차이를 재서 1e-4 를 넘으면 실패로 끝낸다.
import json
import shutil
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from common import CATEGORIES, FIXTURES, read_jsonl, sha256_file


class Logits(torch.nn.Module):
    def __init__(self, model):
        super().__init__()
        self.model = model

    def forward(self, input_ids, attention_mask):
        return self.model(input_ids=input_ids, attention_mask=attention_mask).logits


def main():
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    tok = AutoTokenizer.from_pretrained(src)
    model = AutoModelForSequenceClassification.from_pretrained(src, dtype=torch.float32).eval()
    texts = [r["text"] for r in read_jsonl(FIXTURES / "sentence-dev3.jsonl")[:200]]
    # 기준 확률은 내보내기 전에 낸다. 내보낸 뒤의 모델로 내면 kcelectra 에서 0.8 넘게 달랐다(ONNX 는 새로 불러온 모델과 같음).
    with torch.no_grad():
        reference = [torch.softmax(Logits(model)(**{k: torch.from_numpy(v) for k, v in tok([t], return_tensors="np").items()
                                                   if k != "token_type_ids"}), -1).numpy() for t in texts]
    sample = tok(["예시 문장입니다."], return_tensors="pt")
    torch.onnx.export(Logits(model), (sample["input_ids"], sample["attention_mask"]), str(dst), dynamo=False, opset_version=17,
                      input_names=["input_ids", "attention_mask"], output_names=["logits"],
                      dynamic_axes={"input_ids": {0: "batch", 1: "tokens"}, "attention_mask": {0: "batch", 1: "tokens"},
                                    "logits": {0: "batch"}})
    sess = ort.InferenceSession(str(dst), providers=["CPUExecutionProvider"])
    worst = 0.0
    for t, a in zip(texts, reference):
        enc = tok([t], return_tensors="np")
        b = sess.run(None, {"input_ids": enc["input_ids"].astype(np.int64), "attention_mask": enc["attention_mask"].astype(np.int64)})[0]
        b = np.exp(b - b.max(-1, keepdims=True))
        b /= b.sum(-1, keepdims=True)
        worst = max(worst, float(np.abs(a - b).max()))
    print(f"exported {dst} ({dst.stat().st_size} bytes), max prob diff torch vs onnxruntime over {len(texts)} sentences: {worst:.2e}")
    if worst > 1e-4:
        sys.exit(1)
    if len(sys.argv) == 6:
        write_meta(Path(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]), src, dst)


def write_meta(result, seed, alpha, src, dst):
    rec = json.loads(result.read_text(encoding="utf-8"))
    run = next(r for r in rec["runs"] if r["seed"] == seed and r["alpha"] == alpha)
    if rec["gate"] != "person2":
        sys.exit("개인 조건 v2(person2)로 학습한 결과만 내보낸다")
    refs = json.loads((FIXTURES / "person-references.json").read_text(encoding="utf-8"))
    cand = json.loads((FIXTURES / "candidates.json").read_text(encoding="utf-8"))
    tokenizer = dst.parent / "tokenizer.json"
    shutil.copyfile(src / "tokenizer.json", tokenizer)
    meta = dict(version=1, categories=CATEGORIES, max_tokens=rec["maxlen"], thresholds=[run["thresholds"][c] for c in CATEGORIES],
                person_markers=cand["person_markers"],
                person_references=[p + k for p in refs["possessives"] for k in refs["kin"]]
                + [p + n for p in refs["pointers"] for n in refs["nouns"]] + refs["pronouns"],
                model_sha256=sha256_file(dst), tokenizer_sha256=sha256_file(tokenizer),
                source=dict(base=rec["base"], data=rec["data"], seed=seed, alpha=alpha, lr=rec["lr"], epochs=rec["epochs"]))
    (dst.parent / "classifier.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {dst.parent / 'classifier.json'}")


if __name__ == "__main__":
    main()
