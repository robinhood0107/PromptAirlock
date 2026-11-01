# 판정용(sealed) 문장과 학습 말뭉치 문장의 겹침 검사(Phase 7.9, 결정 #190).
# 사용: python overlap.py <말뭉치 폴더(corpora)>
# sentences/sealed-*.jsonl 의 문장 가운데 sentences/aihub-*.jsonl(학습 14종)에도 있는 문장을 찾는다. 공백을 하나로 줄인 뒤 같은 글이면 겹침이다.
# 학습 문장은 64 bit 해시를 정렬한 배열(약 3,200만 개, 250 MB)로 들고, 판정용 문장을 하나씩 찾는다.
# 겹친 uid 는 sentences/sealed-overlap.txt(저장소 밖)에 쓰고, 화면에는 데이터셋별 개수만 낸다.
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np


def key(text):
    return int.from_bytes(hashlib.blake2b(" ".join(text.split()).encode("utf-8"), digest_size=8).digest(), "little")


def main():
    sent = Path(sys.argv[1]) / "sentences"
    trained = []
    for f in sorted(sent.glob("aihub-*.jsonl")):
        with open(f, encoding="utf-8") as lines:
            trained.extend(key(json.loads(line)["text"]) for line in lines)
    table = np.unique(np.array(trained, dtype=np.uint64))
    del trained
    total, hit, uids = Counter(), Counter(), []
    def check(rows):
        keys = np.array([key(t) for _, _, t in rows], dtype=np.uint64)
        at = np.searchsorted(table, keys).clip(max=len(table) - 1)
        for (ds, uid, _), found in zip(rows, table[at] == keys):
            total[ds] += 1
            if found:
                hit[ds] += 1
                uids.append(uid)

    for f in sorted(sent.glob("sealed-*.jsonl")):
        rows = []
        with open(f, encoding="utf-8") as lines:
            for line in lines:
                r = json.loads(line)
                rows.append((r["ds"], r["uid"], r["text"]))
                if len(rows) == 1_000_000:  # 큰 데이터셋(71788 약 1,800만 문장)을 나눠 읽는다
                    check(rows)
                    rows = []
        check(rows)
    (sent / "sealed-overlap.txt").write_text("".join(u + "\n" for u in uids), encoding="utf-8")
    print(f"training sentences (unique) {len(table)}, sealed sentences {sum(total.values())}, overlapping sealed sentences {len(uids)}")
    for ds in sorted(total, key=lambda d: -total[d]):
        print(f"{ds}\t{total[ds]}\t{hit[ds]}\t{100 * hit[ds] / total[ds]:.3f}%")


if __name__ == "__main__":
    main()
