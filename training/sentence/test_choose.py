# choose.py 의 고르기 규칙 확인(#184 6절). 실행: training\.venv\Scripts\python training\sentence\test_choose.py
from choose import choose, differs


def row(base, score, sel_warn=1.0, dev_warn=1.0, sd=1.0):
    return dict(base=base, mean=dict(score=score, sel_warn=sel_warn, dev_warn=dev_warn), sd=dict(score=sd))


n = {"small": 1, "big": 2}
pick, ok = choose([row("big", 80.0), row("small", 79.2)], n)
assert pick["base"] == "small"  # 1%p 안에서 비기면 작은 바탕
pick, ok = choose([row("big", 80.0), row("small", 78.9)], n)
assert pick["base"] == "big"
pick, ok = choose([row("big", 90.0, dev_warn=3.1), row("small", 70.0, sel_warn=3.0)], n)
assert pick["base"] == "small" and len(ok) == 1  # 정상 경고 3.0 초과는 뺀다
assert choose([row("big", 90.0, sel_warn=4.0)], n) == (None, [])
assert differs(row("a", 75.0, sd=2.0), row("b", 70.9, sd=1.0), "score")
assert not differs(row("a", 75.0, sd=2.0), row("b", 71.0, sd=1.0), "score")
print("ok")
