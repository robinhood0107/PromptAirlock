# common.py 의 판정 계산 확인(알려진 값). 실행: training\.venv\Scripts\python training\sentence\test_common.py
from common import split_sentences, wilson

lo, hi = wilson(24, 800)
assert (round(lo, 1), round(hi, 1)) == (2.0, 4.4), (lo, hi)
lo, hi = wilson(48, 60)
assert (round(lo, 1), round(hi, 1)) == (68.2, 88.2), (lo, hi)
assert wilson(0, 0) == (0.0, 0.0)
assert split_sentences("가.\n\n나") == ["가.", "\n나"]  # C++ sentence_split.hpp 와 같은 결과
assert split_sentences("회의는 3시. 김 과장은 늦어요.") == ["회의는 3시.", " 김 과장은 늦어요."]
assert split_sentences("a.b c") == ["a.b c"]
print("ok")
