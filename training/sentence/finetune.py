# 인코더 전체 미세조정 실험(Phase 7.8, 결정 #174). 제품 빌드·런타임에는 들어가지 않는다.
# 사용(저장소 루트, GPU 판 PyTorch):
#   training\.venv\Scripts\python training\sentence\finetune.py --rules <rules-dev3.jsonl> --out <결과 폴더> --models a,b [--seeds 0,1,2]
# 바탕 모델마다 범주 11 + None 분류 머리를 붙여 학습 전용 셋(train2 + 7.6 학습 셋 + 예시·정상 문장)으로 전체를 학습하고,
# dev3 의 고르는 쪽으로 범주 문턱값을 정한 뒤 재는 쪽으로 평가한다(frozen_head.py 와 같은 평가). 에폭 수는 고정이고
# dev3 를 보고 멈추지 않는다(조기 종료로 dev3 가 학습에 새지 않게).
import argparse
import json
import os
import random
import time
from pathlib import Path

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from common import CATEGORIES, FIXTURES, NONE, Dev3, RealSet, Scorer, evaluate, evaluate_real, pick_thresholds, read_jsonl, verdict

HF = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".cache"))) / "prompt-airlock" / "models" / "hf"
REAL = Path(__file__).resolve().parents[2] / "corpora" / "labels" / "real"

# clean: 학습 데이터 조건이 카드에 상업 가능으로 밝혀진 것(#173). 나머지는 참고 비교 또는 조건 확인 필요.
BASES = {
    "granite107": dict(dir="ibm-granite_granite-embedding-107m-multilingual", clean=True),
    "granite278": dict(dir="ibm-granite_granite-embedding-278m-multilingual", clean=True),
    "granite97r2": dict(dir="ibm-granite_granite-embedding-97m-multilingual-r2", clean=True),
    "granite311r2": dict(dir="ibm-granite_granite-embedding-311m-multilingual-r2", clean=True),
    "mmbert-small": dict(dir="jhu-clsp_mmBERT-small", clean=True),  # 사전학습 데이터 공개(MIT)
    "mmbert-base": dict(dir="jhu-clsp_mmBERT-base", clean=True),
    "ax-encoder": dict(dir="skt_A.X-Encoder-base", clean=False),  # 카드에 데이터 목록 없음
    "xlmr-base": dict(dir="FacebookAI_xlm-roberta-base", clean=False),  # CC100, 조건 확인 필요
    "e5-small": dict(dir="intfloat_multilingual-e5-small", clean=False),  # 비상업 자료 포함(참고)
    "e5-base": dict(dir="intfloat_multilingual-e5-base", clean=False),
    "klue-large": dict(dir="klue_roberta-large", clean=False),  # 한국어 전용, 사전학습 자료 일부 조건 확인 필요
    "kcelectra": dict(dir="beomi_KcELECTRA-base-v2022", clean=False),  # MIT, 사전학습 자료가 뉴스 댓글
}


def training_set(sets=("train2",)):
    """(문장, 클래스) 목록. 합성 셋(train2, train3)을 고르면 7.6 학습 셋과 candidates.json 의 예시·정상 문장을 함께 넣는다.
    real 은 정답을 붙인 말뭉치 학습 몫(corpora/labels/real/train.jsonl, 저장소 밖 로컬 자료)이다."""
    synthetic = [s for s in sets if s != "real"]
    files = [FIXTURES / f"sentence-{s}.jsonl" for s in synthetic] + ([FIXTURES / "sentence-train.jsonl"] if synthetic else [])
    if "real" in sets:
        files.append(REAL / "train.jsonl")
    data = [(r["text"], CATEGORIES.index(r["category"]) if r["sensitive"] else NONE) for f in files for r in read_jsonl(f)]
    if synthetic:
        cand = json.loads((FIXTURES / "candidates.json").read_text(encoding="utf-8"))
        for c, v in cand["categories"].items():
            data += [(e, CATEGORIES.index(c)) for e in v["examples"]]
        data += [(e, NONE) for e in cand["negatives"]]
    return data


def seed_all(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def train(base, data, seed, epochs, lr, batch, maxlen, device):
    seed_all(seed)
    path = HF / BASES[base]["dir"]
    tok = AutoTokenizer.from_pretrained(path)
    # 가중치는 float32 로 둔다. transformers 5 는 설정에 따라 bfloat16 으로 불러오는데, 그러면 작은 학습률의 갱신이 반올림으로 사라진다.
    model = AutoModelForSequenceClassification.from_pretrained(path, num_labels=NONE + 1, dtype=torch.float32).to(device)
    y = np.array([lab for _, lab in data])
    count = np.bincount(y, minlength=NONE + 1)
    weight = torch.tensor(len(y) / ((NONE + 1) * np.maximum(count, 1)), dtype=torch.float32, device=device)
    loss_fn = torch.nn.CrossEntropyLoss(weight=weight)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    steps = epochs * ((len(data) + batch - 1) // batch)
    warm = max(1, steps // 10)
    sched = torch.optim.lr_scheduler.LambdaLR(opt, lambda s: min(1.0, (s + 1) / warm) * max(0.0, (steps - s) / max(1, steps - warm)))
    model.train()
    order = list(range(len(data)))
    losses = []
    for _ in range(epochs):
        random.shuffle(order)
        for i in range(0, len(order), batch):
            idx = order[i:i + batch]
            enc = tok([data[j][0] for j in idx], padding=True, truncation=True, max_length=maxlen, return_tensors="pt").to(device)
            with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
                logits = model(**enc).logits
            loss = loss_fn(logits.float(), torch.tensor([data[j][1] for j in idx], device=device))
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            losses.append(loss.item())
    return tok, model, float(np.mean(losses[-20:]))


@torch.no_grad()
def probabilities(tok, model, texts, maxlen, device, batch=128):
    model.eval()
    out = {}
    for i in range(0, len(texts), batch):
        chunk = texts[i:i + batch]
        enc = tok(chunk, padding=True, truncation=True, max_length=maxlen, return_tensors="pt").to(device)
        with torch.autocast(device_type="cuda", dtype=torch.bfloat16):
            p = torch.softmax(model(**enc).logits.float(), dim=-1).cpu().numpy()
        out.update(zip(chunk, p))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--models", default=",".join(BASES))
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--alpha", default="0.04,0.06,0.08")
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--maxlen", type=int, default=128)
    ap.add_argument("--gate", default="person", choices=["person", "person2"])
    ap.add_argument("--data", default="train2", help="학습 셋을 + 로 잇는다: train2, train3, real(예: train2+train3+real)")
    ap.add_argument("--real-rules", default="", help="정답 붙인 말뭉치 셋의 규칙 판정(sentence_measure --lines 결과). 주면 문턱값을 dev3 고르는 쪽 + 말뭉치 dev 로 정하고 말뭉치 test 도 잰다")
    ap.add_argument("--save", action="store_true", help="학습한 모델을 <out>/<바탕>-seed<N> 에 저장(ONNX 내보내기용)")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    device = "cuda"
    dev = Dev3(a.rules)
    texts = dev.texts(False)
    real = RealSet(REAL, a.real_rules) if a.real_rules else None
    if real:
        texts = sorted(set(texts) | set(real.texts()))
    data = training_set(a.data.split("+"))
    for base in a.models.split(","):
        runs = []
        for seed in map(int, a.seeds.split(",")):
            start = time.perf_counter()
            tok, model, loss = train(base, data, seed, a.epochs, a.lr, a.batch, a.maxlen, device)
            train_s = time.perf_counter() - start
            train_probs = probabilities(tok, model, [t for t, _ in data], a.maxlen, device)
            train_acc = float(np.mean([train_probs[t].argmax() == lab for t, lab in data]))
            probs = probabilities(tok, model, texts, a.maxlen, device)
            for alpha in map(float, a.alpha.split(",")):
                sc = Scorer(probs, False, gate=a.gate)
                sc.thresholds = pick_thresholds(dev, sc, alpha, real.parts["dev"] if real else ())
                m = evaluate(dev, sc, "test")
                runs.append(dict(seed=seed, alpha=alpha, loss=loss, train_acc=train_acc, train_seconds=train_s, thresholds=sc.thresholds,
                                 test=m, select=evaluate(dev, sc, "select"), verdict=verdict(m)))
                if real:
                    runs[-1]["real"] = {name: evaluate_real(rows, sc) for name, rows in real.parts.items()}
                    runs[-1]["real"]["test+targeted"] = evaluate_real(real.parts["test"] + real.parts["test-targeted"], sc)
                    rm = runs[-1]["real"]
                    print(f"  real dev recall {rm["dev"]["recall"]["pct"]:.1f} warn {rm["dev"]["benign_warn"]["pct"]:.1f} | "
                          f"test recall {rm["test"]["recall"]["pct"]:.1f} warn {rm["test"]["benign_warn"]["pct"]:.1f} "
                          f"(high {rm["test"]["benign_warn"]["high"]:.1f}) | targeted recall {rm["test-targeted"]["recall"]["pct"]:.1f} "
                          f"hard-none warn {rm["test-targeted"]["benign_warn"]["pct"]:.1f}", flush=True)
                print(f"{base} seed{seed} a{alpha:g}: evasive {m['evasive']['pct']:.1f} (low {m['evasive']['low']:.1f}) "
                      f"warn {m['benign_warn']['pct']:.1f} (high {m['benign_warn']['high']:.1f}) "
                      + " ".join(f"{k} {v['pct']:.1f}" for k, v in m["axes"].items())
                      + f" frames6-7 {m['evasive_frames_6_7']['pct']:.1f} train_acc {100 * train_acc:.1f} pass {runs[-1]['verdict']['all']}",
                      flush=True)
            if a.save:
                model.save_pretrained(out / f"{base}-seed{seed}")
                tok.save_pretrained(out / f"{base}-seed{seed}")
            del model
            torch.cuda.empty_cache()
        rec = dict(base=base, clean=BASES[base]["clean"], data=a.data, gate=a.gate, train_n=len(data), epochs=a.epochs, lr=a.lr, batch=a.batch, maxlen=a.maxlen,
                   torch=torch.__version__, runs=runs)
        (out / f"{base}.json").write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
