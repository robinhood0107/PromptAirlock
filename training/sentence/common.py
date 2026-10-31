# 문장 판별기 오프라인 실험 공통 부분(결정 #174). 제품 빌드·런타임에는 들어가지 않는다.
# 셋 읽기, 규칙 판정(sentence_measure --rules-out 결과) 합치기, 문장 나누기, Wilson 구간, dev3 평가와 지름길 7축 집계.
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "sentence"
CATEGORIES = list(json.loads((FIXTURES / "candidates.json").read_text(encoding="utf-8"))["categories"].keys())
NONE = len(CATEGORIES)  # 마지막 클래스가 None
MUST_BLOCK = {"direct", "variant", "split", "evasive"}

# ADR 0022 "다음 판정" 수치(측정 전 고정). 개발 셋에서는 참고 판정으로만 쓴다.
CRITERIA = {"evasive_low": 70.0, "category_low": 55.0, "benign_warn_high": 5.0, "flip_max": 10.0, "add_max": 5.5}


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def split_sentences(text):
    # tests/measure/sentence_split.hpp 와 같은 규칙(마침표·물음표·느낌표·줄바꿈 뒤, 다음이 공백·줄바꿈이거나 끝).
    out, cur = [], ""
    for i, c in enumerate(text):
        cur += c
        if c in ".?!\n" and (i + 1 == len(text) or text[i + 1] in " \n"):
            if cur.strip(" \n"):
                out.append(cur)
            cur = ""
    if cur.strip(" \n"):
        out.append(cur)
    return out


def wilson(k, n, z=1.96):
    # 95% Wilson 구간(백분율). C++ 측정 도구의 wilson() 과 같은 식.
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    center = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return (100.0 * max(0.0, center - half), 100.0 * min(1.0, center + half))


def rate(k, n):
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "pct": 100.0 * k / n if n else 0.0, "low": lo, "high": hi}


def half_of(key):
    # dev3 를 사실 단위로 둘로 나눈다. 같은 사실의 복사본이 고르는 쪽과 재는 쪽에 갈라 들어가지 않게 한다.
    return "select" if int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16) % 2 == 0 else "test"


class Dev3:
    """dev3 셋, 지름길 쌍, 규칙 판정, 학습 재료를 한곳에 모은다."""

    def __init__(self, rules_path):
        self.records = read_jsonl(FIXTURES / "sentence-dev3.jsonl")
        self.pairs = read_jsonl(FIXTURES / "shortcut-dev3.jsonl")
        rules = {r["key"]: r for r in read_jsonl(rules_path)}
        self.rules = rules
        for r in self.records:
            r["rule"] = rules[r["id"]]
            r["half"] = half_of(r["fact"] or r["text"])
        by_id = {r["id"]: r for r in self.records}
        for n, p in enumerate(self.pairs):
            p["ra"], p["rb"] = rules[f"pair{n}:a"], rules[f"pair{n}:b"]
            src = by_id.get(p["id"])
            p["half"] = src["half"] if src else half_of(p["a"])
        self.train = [(rules["train:" + r["id"]], CATEGORIES.index(r["category"]) if r["sensitive"] else NONE)
                      for r in read_jsonl(FIXTURES / "sentence-train.jsonl")]
        for key, r in rules.items():
            if key.startswith("ex:"):
                self.train.append((r, CATEGORIES.index(key.split(":")[1])))
            elif key.startswith("neg:"):
                self.train.append((r, NONE))

    def texts(self, masked):
        """임베딩이 필요한 모든 문장(문장 나누기 뒤). masked 면 NER 사람 범위를 가린 문장."""
        field = "masked" if masked else "text"
        out = set()
        for r in self.rules.values():
            out.update(split_sentences(r[field]))
        return sorted(out)


def rule_block(rule, sensitive, category):
    # 민감 문장은 맞는 종류로 막아야 막은 것이고(인증 정보는 Credential, 나머지는 민감정보), 정상 문장은 무엇이든 나오면 막은 것이다.
    if rule["error"]:
        return True
    if sensitive:
        return rule["credential"] if category == "Credential" else rule["sensitive"]
    return rule["credential"] or rule["sensitive"]


class Scorer:
    """문장별 확률(probs: 문장 -> 클래스별 확률)로 글 하나의 점수와 판정을 낸다(--split --gate 와 같은 방식)."""

    def __init__(self, probs, masked, thresholds=None):
        self.probs, self.masked, self.thresholds = probs, masked, thresholds

    def score(self, rule):
        best, pred = -1.0, None
        for s in split_sentences(rule["masked" if self.masked else "text"]):
            p = self.probs[s]
            for c in range(NONE):
                if p[c] > best:
                    best, pred = p[c], CATEGORIES[c]
        return best, pred

    def warn(self, rule):
        score, pred = self.score(rule)
        usable = rule["person"] or pred == "Credential"
        return usable and score >= self.thresholds[pred]

    def flagged(self, rule, sensitive=False, category=None):
        return rule_block(rule, sensitive, category) or self.warn(rule)


def pick_thresholds(dev, scorer, alpha):
    # 범주마다 고르는 쪽 정상 문장(규칙이 막지 않았고 판별기를 쓰는 것)의 점수 (1 - alpha) 분위수. C++ per_category 와 같은 식.
    scores = {c: [] for c in CATEGORIES}
    for r in dev.records:
        if r["half"] != "select" or r["sensitive"] or rule_block(r["rule"], False, None):
            continue
        s, pred = scorer.score(r["rule"])
        if r["rule"]["person"] or pred == "Credential":
            scores[pred].append(s)
    th = {}
    for c, v in scores.items():
        if not v:
            th[c] = 1e9
            continue
        v.sort()
        k = math.ceil((1.0 - alpha) * len(v))
        th[c] = v[-1] + 1e-6 if k >= len(v) else v[k]
    return th


def evaluate(dev, scorer, half="test"):
    rows = [r for r in dev.records if r["half"] == half]
    out = {}
    for group in sorted({r["group"] for r in rows}):
        g = [r for r in rows if r["group"] == group]
        out[group] = rate(sum(scorer.flagged(r["rule"], r["sensitive"], r["category"]) for r in g), len(g))
    benign = [r for r in rows if not r["sensitive"]]
    out["benign_flagged"] = rate(sum(scorer.flagged(r["rule"]) for r in benign), len(benign))
    out["benign_warn"] = rate(sum(scorer.warn(r["rule"]) and not rule_block(r["rule"], False, None) for r in benign), len(benign))
    out["rule_false_block"] = rate(sum(rule_block(r["rule"], False, None) for r in benign), len(benign))
    ev = [r for r in rows if r["group"] == "evasive"]
    out["evasive_by_category"] = {c: rate(sum(scorer.flagged(r["rule"], True, c) for r in ev if r["category"] == c),
                                          sum(r["category"] == c for r in ev)) for c in CATEGORIES}
    # 틀 일반화: 학습에 쓰는 틀(0-5)과 개발 셋에만 둔 틀(6, 7)의 돌려 말함 재현율.
    for name, frames in (("evasive_frames_0_5", range(0, 6)), ("evasive_frames_6_7", (6, 7))):
        e = [r for r in ev if r["frame"] in frames]
        out[name] = rate(sum(scorer.flagged(r["rule"], True, r["category"]) for r in e), len(e))
    axes = {}
    for axis in sorted({p["axis"] for p in dev.pairs}):
        ps = [p for p in dev.pairs if p["axis"] == axis and p["half"] == half]
        if ps[0]["expect"] == "same":
            k = sum(scorer.flagged(p["ra"], p["sensitive"], p["category"]) != scorer.flagged(p["rb"], p["sensitive"], p["category"])
                    for p in ps)
        elif ps[0]["expect"] == "benign":
            k = sum(scorer.flagged(p["rb"]) for p in ps)
        else:
            k = sum(scorer.flagged(p["rb"], True, p["category"]) for p in ps)
        axes[axis] = rate(k, len(ps))
    out["axes"] = axes
    return out


def verdict(m):
    """ADR 0022 수치에 비춘 참고 판정(개발 셋이라 최종 판정이 아니다). 각 항목의 통과 여부와 전체."""
    checks = {
        "evasive_low": m["evasive"]["low"] >= CRITERIA["evasive_low"],
        "category_low": min(v["low"] for v in m["evasive_by_category"].values()) >= CRITERIA["category_low"],
        "benign_warn_high": m["benign_warn"]["high"] <= CRITERIA["benign_warn_high"],
    }
    for axis, v in m["axes"].items():
        if axis == "mix":
            continue
        limit = CRITERIA["add_max"] if axis.endswith("_add") else CRITERIA["flip_max"]
        checks[f"axis_{axis}"] = v["pct"] <= limit
    checks["all"] = all(checks.values())
    return checks
