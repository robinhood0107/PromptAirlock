# 임베딩 고정 + 선형 분류기 실험(Phase 7.7-2 기준선, 결정 #174). 제품 빌드·런타임에는 들어가지 않는다.
# 사용(저장소 루트):
#   training\.venv\Scripts\python training\sentence\frozen_head.py --rules <rules-dev3.jsonl> --out <결과 폴더> [--models a,b] [--mask]
# 모델마다 ONNX 로 문장 벡터를 만들고(C++ 측정 도구와 같은 풀링·접두어), 7.6 과 같은 방식(학습 전용 셋 + 예시, 표준화,
# 클래스 균형 가중치, 전체 묶음 경사 하강 2000번)으로 범주 11 + None 분류기를 학습한다. 학습 데이터를 seed 로 다시 뽑아
# (seed 0 은 원래 데이터) 흩어짐을 보고, 문턱값은 dev3 의 고르는 쪽에서만 고르고 재는 쪽으로 평가한다.
import argparse
import json
import os
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

from common import CATEGORIES, NONE, Dev3, Scorer, evaluate, pick_thresholds, sha256_file, verdict

BASE = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".cache"))) / "prompt-airlock" / "models" / "phase75"

# clean: 학습 데이터 조건이 카드에 상업 가능으로 밝혀진 것(#173). 나머지는 참고 비교.
MODELS = {
    "granite107": dict(dir="ibm-granite_granite-embedding-107m-multilingual", onnx="model.onnx", tok="tokenizer.json", pool="cls", prefix="", clean=True),
    "granite278": dict(dir="ibm-granite_granite-embedding-278m-multilingual", onnx="model.onnx", tok="tokenizer.json", pool="cls", prefix="", clean=True),
    "granite97r2": dict(dir="ibm-granite_granite-embedding-97m-multilingual-r2", onnx="onnx/model.onnx", tok="tokenizer.json", pool="cls", prefix="", clean=True),
    "granite97r2q": dict(dir="ibm-granite_granite-embedding-97m-multilingual-r2", onnx="onnx/model_quint8_avx2.onnx", tok="tokenizer.json", pool="cls", prefix="", clean=True),
    "granite311r2": dict(dir="ibm-granite_granite-embedding-311m-multilingual-r2", onnx="onnx/model.onnx", tok="tokenizer.json", pool="cls", prefix="", clean=True),
    "granite311r2q": dict(dir="ibm-granite_granite-embedding-311m-multilingual-r2", onnx="onnx/model_quint8_avx2.onnx", tok="tokenizer.json", pool="cls", prefix="", clean=True),
    "e5": dict(dir="intfloat_multilingual-e5-small/onnx", onnx="model.onnx", tok="tokenizer.json", pool="mean", prefix="query: ", clean=False),
    "e5q": dict(dir="intfloat_multilingual-e5-small/onnx", onnx="model_qint8_avx512_vnni.onnx", tok="tokenizer.json", pool="mean", prefix="query: ", clean=False),
    "e5base": dict(dir="intfloat_multilingual-e5-base/onnx", onnx="model.onnx", tok="tokenizer.json", pool="mean", prefix="query: ", clean=False),
    "minilm": dict(dir="sentence-transformers_paraphrase-multilingual-MiniLM-L12-v2", onnx="onnx/model.onnx", tok="tokenizer.json", pool="mean", prefix="", clean=False),
    "arctic": dict(dir="Snowflake_snowflake-arctic-embed-m-v2.0", onnx="onnx/model_quantized.onnx", tok="tokenizer.json", pool="cls", prefix="query: ", clean=False),
}


class Encoder:
    def __init__(self, spec):
        d = BASE / spec["dir"]
        self.spec, self.path = spec, d / spec["onnx"]
        self.tok = Tokenizer.from_file(str(d / spec["tok"]))
        self.tok.enable_truncation(512)
        self.tok.no_padding()
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1  # C++ 측정과 같게 스레드 1
        self.sess = ort.InferenceSession(str(self.path), opts, providers=["CPUExecutionProvider"])
        self.inputs = [i.name for i in self.sess.get_inputs()]

    def embed(self, text):
        e = self.tok.encode(self.spec["prefix"] + text)
        ids = np.array([e.ids], dtype=np.int64)
        feed = {"input_ids": ids, "attention_mask": np.ones_like(ids)}
        if "token_type_ids" in self.inputs:
            feed["token_type_ids"] = np.zeros_like(ids)
        out = self.sess.run(None, {k: v for k, v in feed.items() if k in self.inputs})[0][0]
        v = out[0] if self.spec["pool"] == "cls" else out.mean(axis=0)
        return v / np.linalg.norm(v)


def embeddings(name, texts, cache_dir):
    """문장 -> 벡터. 모델 파일 해시별 캐시에 없는 문장만 새로 계산한다."""
    enc = Encoder(MODELS[name])
    digest = sha256_file(enc.path)
    cache = cache_dir / f"{name}-{digest[:16]}.npz"
    known = {}
    if cache.exists():
        z = np.load(cache, allow_pickle=False)
        known = dict(zip(z["texts"].tolist(), z["vecs"]))
    missing = [t for t in texts if t not in known]
    start = time.perf_counter()
    for t in missing:
        known[t] = enc.embed(t)
    if missing:
        keys = sorted(known)
        np.savez(cache, texts=np.array(keys), vecs=np.stack([known[k] for k in keys]))
    return known, digest, (time.perf_counter() - start) / max(1, len(missing)) * 1000.0


def train_head(x, y, l2, steps=2000, lr=0.5):
    # C++ 측정 도구(sentence_candidate_measure --head)와 같은 식: 표준화, 클래스 균형 가중치, 0 에서 시작, 전체 묶음 경사 하강.
    mean = x.mean(axis=0)
    std = x.std(axis=0) + 1e-8
    z = np.hstack([(x - mean) / std, np.ones((len(x), 1))])
    classes = NONE + 1
    count = np.bincount(y, minlength=classes).astype(np.float64)
    w_sample = len(y) / (classes * count[y])
    onehot = np.eye(classes)[y]
    w = np.zeros((classes, z.shape[1]))
    reg = np.ones(z.shape[1])
    reg[-1] = 0.0  # 절편은 규제하지 않는다
    total = w_sample.sum()
    for _ in range(steps):
        logit = z @ w.T
        logit -= logit.max(axis=1, keepdims=True)
        p = np.exp(logit)
        p /= p.sum(axis=1, keepdims=True)
        grad = ((p - onehot) * w_sample[:, None]).T @ z
        w -= lr * (grad / total + l2 * w * reg)
    logit = z @ w.T
    logit -= logit.max(axis=1, keepdims=True)
    logp = logit - np.log(np.exp(logit).sum(axis=1, keepdims=True))
    loss = -(w_sample * logp[np.arange(len(y)), y]).sum() / total
    acc = float((logit.argmax(axis=1) == y).mean())
    return dict(w=w, mean=mean, std=std, loss=float(loss), train_acc=acc)


def predict(head, x):
    z = np.hstack([(x - head["mean"]) / head["std"], np.ones((len(x), 1))])
    logit = z @ head["w"].T
    logit -= logit.max(axis=1, keepdims=True)
    p = np.exp(logit)
    return p / p.sum(axis=1, keepdims=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--models", default=",".join(MODELS))
    ap.add_argument("--mask", action="store_true")
    ap.add_argument("--l2", default="0.1,1")
    ap.add_argument("--alpha", default="0.04,0.06,0.08")
    ap.add_argument("--seeds", type=int, default=5)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    cache = Path(__file__).resolve().parents[1] / ".cache"
    cache.mkdir(exist_ok=True)
    dev = Dev3(a.rules)
    field = "masked" if a.mask else "text"
    texts = dev.texts(a.mask)
    train_texts = [r[field] for r, _ in dev.train]
    for name in a.models.split(","):
        vec, digest, ms = embeddings(name, sorted(set(texts) | set(train_texts)), cache)
        x = np.stack([vec[t] for t in train_texts])
        y = np.array([lab for _, lab in dev.train])
        sent = sorted(set(texts))
        xs = np.stack([vec[t] for t in sent])
        for l2 in map(float, a.l2.split(",")):
            runs = []
            for seed in range(a.seeds):
                rng = np.random.default_rng(seed)
                idx = np.arange(len(y)) if seed == 0 else rng.integers(0, len(y), len(y))
                head = train_head(x[idx], y[idx], l2)
                probs = dict(zip(sent, predict(head, xs)))
                for alpha in map(float, a.alpha.split(",")):
                    sc = Scorer(probs, a.mask)
                    sc.thresholds = pick_thresholds(dev, sc, alpha)
                    m = evaluate(dev, sc, "test")
                    sel = evaluate(dev, sc, "select")
                    runs.append(dict(seed=seed, alpha=alpha, loss=head["loss"], train_acc=head["train_acc"], thresholds=sc.thresholds,
                                     test=m, select=sel, verdict=verdict(m)))
            rec = dict(model=name, clean=MODELS[name]["clean"], onnx_sha256=digest, embed_ms_python=ms, mask=a.mask, l2=l2,
                       train_n=int(len(y)), runs=runs)
            tag = f"{name}{'-mask' if a.mask else ''}-l2{l2:g}"
            (out / f"{tag}.json").write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
            for alpha in map(float, a.alpha.split(",")):
                rs = [r for r in runs if r["alpha"] == alpha]
                ev = [r["test"]["evasive"]["pct"] for r in rs]
                bw = [r["test"]["benign_warn"]["pct"] for r in rs]
                nm = [r["test"]["axes"]["name"]["pct"] for r in rs]
                pa = [r["test"]["axes"]["person_add"]["pct"] for r in rs]
                ta = [r["test"]["axes"]["topic_add"]["pct"] for r in rs]
                ok = sum(r["verdict"]["all"] for r in rs)
                print(f"{tag} a{alpha:g}: evasive {np.mean(ev):.1f}±{np.std(ev):.1f} warn {np.mean(bw):.1f}±{np.std(bw):.1f} "
                      f"name {np.mean(nm):.1f} person_add {np.mean(pa):.1f} topic_add {np.mean(ta):.1f} pass {ok}/{len(rs)}", flush=True)


if __name__ == "__main__":
    main()
