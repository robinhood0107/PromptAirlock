# 미세조정한 분류기를 ONNX 로 내보낸다(Phase 7.8-1, 결정 #174). 제품은 이 ONNX 를 C++ ONNX Runtime 으로 돌린다.
# 사용: training\.venv\Scripts\python training\sentence\export.py <저장한 모델 폴더> <내보낼 .onnx>
# 입력 input_ids, attention_mask(길이 가변), 출력 logits [묶음, 12]. 내보낸 뒤 같은 문장들로 PyTorch 와 ONNX Runtime 의
# 확률 차이를 재서 1e-4 를 넘으면 실패로 끝낸다.
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from common import FIXTURES, read_jsonl


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
    sample = tok(["예시 문장입니다."], return_tensors="pt")
    torch.onnx.export(Logits(model), (sample["input_ids"], sample["attention_mask"]), str(dst), dynamo=False, opset_version=17,
                      input_names=["input_ids", "attention_mask"], output_names=["logits"],
                      dynamic_axes={"input_ids": {0: "batch", 1: "tokens"}, "attention_mask": {0: "batch", 1: "tokens"},
                                    "logits": {0: "batch"}})
    sess = ort.InferenceSession(str(dst), providers=["CPUExecutionProvider"])
    texts = [r["text"] for r in read_jsonl(FIXTURES / "sentence-dev3.jsonl")[:200]]
    worst = 0.0
    for t in texts:
        enc = tok([t], return_tensors="np")
        a = torch.softmax(Logits(model)(torch.from_numpy(enc["input_ids"]), torch.from_numpy(enc["attention_mask"])), -1).detach().numpy()
        b = sess.run(None, {"input_ids": enc["input_ids"].astype(np.int64), "attention_mask": enc["attention_mask"].astype(np.int64)})[0]
        b = np.exp(b - b.max(-1, keepdims=True))
        b /= b.sum(-1, keepdims=True)
        worst = max(worst, float(np.abs(a - b).max()))
    print(f"exported {dst} ({dst.stat().st_size} bytes), max prob diff torch vs onnxruntime over {len(texts)} sentences: {worst:.2e}")
    if worst > 1e-4:
        sys.exit(1)


if __name__ == "__main__":
    main()
