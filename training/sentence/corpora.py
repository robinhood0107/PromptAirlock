# NIA 데이터 공유 플랫폼(aihub.or.kr) 말뭉치를 문장 단위 JSONL 로 바꾼다(결정 #181). 학습 데이터 준비 전용이며 제품에는 들어가지 않는다.
# 사용: python corpora.py <말뭉치 폴더(corpora)> [--only 86,98] [--max-docs N] [--set sealed]
#   --set sealed 는 판정용 데이터셋(corpora/sealed/<번호>/, 결정 #190)을 sentences/sealed-<번호>.jsonl 과 stats-sealed.json 으로 쓴다.
# 원본 zip 은 풀지 않고 그대로 읽어 <말뭉치 폴더>/sentences/aihub-<번호>.jsonl 과 개수 요약(stats.json)을 쓴다.
# 원문은 저장소·화면에 남기지 않는다(플랫폼 이용정책: 제3자 제공·재배포 제한). 화면에는 개수만 내고 출력 파일도 저장소 밖(git 제외)에 둔다.
# 한 줄: {"uid", "ds", "split"(플랫폼의 학습/검증 구분), "doc", "spk", "text", "hint"(데이터셋이 준 분류 코드)}
import argparse
import base64
import csv
import hashlib
import json
import re
import zipfile
from collections import Counter
from pathlib import Path

from common import split_sentences


def fixname(info):
    if info.flag_bits & 0x800:
        return info.filename
    try:
        return info.filename.encode("cp437").decode("cp949")
    except UnicodeError:
        return info.filename


def members(ds_dir, kind, suffix=".json"):
    """(플랫폼 학습/검증, 파일 이름, 읽기 함수)를 낸다. kind: 라벨링(label) 또는 원천(source).
    zip 이 있으면 zip 에서, 지웠으면 MANIFEST.json 에 적힌 풀어 둔 위치에서 읽는다(학습/검증 구분도 원장 값)."""
    root = ds_dir.parents[1]
    manifest = root / "MANIFEST.json" if ds_dir.parent.name == "aihub" else ds_dir.parent / "MANIFEST.json"
    zips = json.loads(manifest.read_text(encoding="utf-8"))[ds_dir.name]["zips"]
    for rel, info in sorted(zips.items()):
        if info["kind"] != kind:
            continue
        z = root / rel
        if z.exists():
            with zipfile.ZipFile(z) as zf:
                for i in zf.infolist():
                    name = fixname(i)
                    if not i.is_dir() and name.lower().endswith(suffix):
                        yield info["split"], name, lambda i=i, zf=zf: zf.read(i).decode("utf-8-sig", "replace")
            continue
        path = (info.get("extracted") or {}).get("path")
        if not path:
            continue  # 음성만 든 zip
        packed = (root / path).with_suffix(".source-documents.jsonl")
        if packed.exists():  # 71807 원천: 작은 JSON 들을 한 줄씩 옮긴 파일
            with open(packed, encoding="utf-8") as f:
                for line in f:
                    row = json.loads(line)
                    if row["file"].lower().endswith(suffix):
                        text = row["content"] if "content" in row else base64.b64decode(row["content_b64"]).decode("utf-8-sig", "replace")
                        yield info["split"], row["file"], lambda text=text: text.removeprefix("﻿")
            continue
        for p in sorted((root / path).rglob("*")):
            if p.is_file() and p.name.lower().endswith(suffix):
                yield info["split"], p.relative_to(root / path).as_posix(), lambda p=p: p.read_bytes().decode("utf-8-sig", "replace")


EMPTY = Counter()


def load(read, ds=""):
    text = read()
    if not text.strip():
        EMPTY[ds] += 1  # 원본에 빈 파일이 있다
        return []
    return json.loads(text)


SPEAKER = re.compile(r"^\s*([^:：]{1,8})\s*[:：]\s*(.*)$")


def dialogue_lines(content):
    """'고객: …', '상담원: …' 같은 줄을 (화자, 말) 로 나눈다."""
    for line in content.splitlines():
        if line[:3] in ("TX ", "RX "):  # 71926: TX 는 상담원 쪽(인사말로 시작), RX 는 고객 쪽
            yield ("agent" if line[:2] == "TX" else "client"), line[3:]
            continue
        m = SPEAKER.match(line)
        if m:
            who = m.group(1).strip()
            yield {"고객": "client", "손님": "client", "상담사": "agent", "상담원": "agent"}.get(who, who), m.group(2)
        elif line.strip():
            yield "", line


# 데이터셋마다 (split, doc, spk, text, hint) 를 내는 함수. text 는 문장 나누기 전의 발화·문단이다.
def ds86(d):
    for split, _, read in members(d, "label"):
        for o in load(read):
            hint = {"situation": o["profile"]["emotion"]["situation"], "emotion": o["profile"]["emotion"]["type"],
                    "persona": o["profile"]["persona"]["human"]}
            doc = o["talk"]["id"]["talk-id"]
            for k, v in o["talk"]["content"].items():
                if v:
                    yield split, doc, "self" if k.startswith("HS") else "system", v, hint


def ds98(d):
    for split, name, read in members(d, "label"):
        for r in load(read):
            hint = {"domain": r.get("도메인"), "category": r.get("카테고리"), "intent": r.get("고객의도")}
            for field, spk in (("고객질문(요청)", "client"), ("고객답변", "client"), ("상담사질문(요청)", "agent"), ("상담사답변", "agent")):
                if r.get(field):
                    yield split, f"{name}:{r.get('대화셋일련번호')}", spk, r[field], hint


def ds114(d):
    for split, _, read in members(d, "label"):
        for o in load(read)["data"]:
            hint = {"topic": o["header"]["dialogueInfo"].get("topic")}
            for u in o["body"]:
                yield split, o["header"]["dialogueInfo"]["dialogueID"], u["participantID"], u["utterance"], hint


def ds543(d):
    for split, _, read in members(d, "label"):
        for info in load(read)["info"]:
            a = info["annotations"]
            for line in a["lines"]:
                yield split, info["filename"], line["speaker"]["id"], line["text"], {"subject": a.get("subject"), "act": line.get("speechAct")}


def ds558(d):
    for split, _, read in members(d, "label"):
        for o in load(read):
            for s in o["sentences"]:
                yield split, o["id"], str(s["speaker"]), s["text"], {"types": s["types"], "immoral": s["is_immoral"]}


def ds569(d):
    seen = set()
    for split, _, read in members(d, "source"):
        for doc in load(read)["data"]:
            if doc["doc_id"] in seen:
                continue  # 같은 행정 문서가 여러 질의 유형 파일에 겹쳐 들어 있다
            seen.add(doc["doc_id"])
            for p in doc["paragraphs"]:
                yield split, doc["doc_id"], "document", p["context"], {"class": doc["doc_class"]["class"], "source": doc["doc_source"]}


def ds580(d):
    for split, name, read in members(d, "label"):
        o = load(read)
        info = o.get("info", {})
        hint = {"field": info.get("caseField"), "case": info.get("caseNm")}
        for section in ("facts", "dcss", "mentionedItems", "disposal", "close"):
            for k, v in (o.get(section) or {}).items():
                for t in v if isinstance(v, list) else []:
                    yield split, name, "court", t, {**hint, "section": f"{section}.{k}"}


def ds619(d):
    for split, name, read in members(d, "label"):
        for doc in load(read)["documents"]:
            yield split, doc["id"], "citizen", doc["Q_refined"], {"intent": doc["labeling"]["intent"].get("category"), "dept": doc["labeling"].get("department")}


REPAIRED = Counter()
UNREADABLE = Counter()


def ds71806(d):
    for split, _, read in members(d, "label"):
        text = read()
        if not text.strip():
            EMPTY["71806"] += 1
            continue
        try:
            o = json.loads(text)
        except json.JSONDecodeError:
            # 원본 14개 파일은 summary 칸의 따옴표가 깨져 있다. 그 칸만 빼고 다시 읽는다(발화·증상 표시는 그대로).
            try:
                o = json.loads(re.sub(r'"summary":.*?\n(\s*"silence")', r"\1", text, count=1, flags=re.S))
                REPAIRED["71806"] += 1
            except json.JSONDecodeError:
                UNREADABLE["71806"] += 1  # 고쳐도 읽을 수 없는 파일은 건너뛰고 개수만 남긴다
                continue
        for p in o["paragraph"]:
            marks = {k: v for k, v in p.items() if isinstance(v, int) and k not in ("start_point", "end_point", "character_count", "cps")}
            yield split, o["id"], "client" if p["paragraph_speaker"] == "내담자" else "counselor", p["paragraph_text"], {"class": o["class"], **marks}


def ds71807(d, limit):
    n = 0
    for split, name, read in members(d, "source"):
        if "메타데이터" not in name:
            continue
        for info in load(read)["info"]:
            yield split, info["document_id"], "document", info["contents_text"], {"org_type": info.get("organization_type"), "doc": info.get("document_name")}
        n += 1
        if limit and n >= limit:
            return


def consulting(d, content_key="consulting_content"):
    for split, name, read in members(d, "source"):
        o = load(read)
        for r in o if isinstance(o, list) else [o]:
            src = r.get("source") if isinstance(r.get("source"), dict) else r
            text = src.get(content_key) or ""
            doc = src.get("source_id") or name
            hint = {"category": src.get("consulting_category") or (r.get("consulting") or {}).get("consulting_category"),
                    "topic": (r.get("consulting") or {}).get("consulting_topic"), "source": src.get("source") or src.get("source_institution")}
            for spk, line in dialogue_lines(text):
                yield split, doc, spk, line, hint


def ds71968(d):
    for split, name, read in members(d, "label"):
        o = load(read)
        hint = {"class": o["info"].get("caseClass"), "case": o["info"].get("caseNm"), "type": o["info"].get("dataType")}
        for s in o.get("sections", []):
            yield split, o["info"].get("caseNoID") or name, "court", s.get("text", ""), {**hint, "section": s.get("title")}


# 판정용(sealed) 데이터셋. 학습에는 쓰지 않는다(결정 #190).
def jload(read, ds):
    """깨진 JSON 파일은 건너뛰고 개수만 남긴다(544 원본에 있다). 빈 파일은 빈 dict."""
    try:
        return load(read, ds) or {}
    except json.JSONDecodeError:
        UNREADABLE[ds] += 1
        return {}


def utterances(d):
    """71302·71305·71694: 라벨링 JSON 의 utterances[].text."""
    for split, name, read in members(d, "label"):
        o = jload(read, d.name)
        if not o:
            continue
        info = o.get("info", {})
        hint = {k: info.get(k) for k in ("topic", "relation", "situation", "keyword") if info.get(k)}
        for u in o.get("utterances", []):
            yield split, info.get("id") or name, u.get("speaker") or str(u.get("persona_id") or u.get("role") or ""), u.get("text"), hint


def ds71630(d):
    for split, name, read in members(d, "label"):
        o = jload(read, d.name)
        if not o:
            continue
        hint = {"topic": o.get("topicInfo", {}).get("topicTitle")}
        for session in o.get("sessionInfo", []):
            for u in session.get("dialog", []):
                yield split, o.get("FileInfo", {}).get("filename") or name, u.get("speaker"), u.get("utterance"), hint


def ds71618(d):
    for split, name, read in members(d, "source"):
        if "상담기록" not in name:
            continue  # 학생 기초 정보(설문 점수)는 문장이 아니다
        o = jload(read, d.name)
        for r in (o.values() if isinstance(o, dict) else o):
            meta = r.get("meta", {})
            for c in r.get("conversation", []):
                for u in c.get("utterances", []):
                    who = "student" if str(u.get("speaker_idx", "")).startswith("S") else "counselor"
                    yield split, f"{meta.get('student_idx')}-{meta.get('counseling_idx')}", who, u.get("utterance"), {"category": c.get("conv_category")}


def ds71791(d):
    for split, name, read in members(d, "source"):
        o = jload(read, d.name)
        for t in o.get("test", []):
            yield split, o.get("meta", {}).get("tester_id") or name, "student", t.get("answer_full"), {"question": t.get("question_id")}


def ds544(d):
    for split, _, read in members(d, "label"):
        for info in jload(read, d.name).get("info", []):
            a = info["annotations"]
            for line in a["lines"]:
                # 줄 앞의 "A." 같은 화자 표시를 뗀다
                yield split, info["filename"], line["speaker"]["id"], re.sub(r"^[A-Z]\.", "", line["text"]), {"subject": a.get("subject")}


def ds71875(d):
    for split, name, read in members(d, "label"):
        o = jload(read, d.name)
        yield split, f"qa-{o.get('qa_id')}", "question", o.get("question"), {"domain": o.get("domain")}
    for split, name, read in members(d, "source"):
        o = jload(read, d.name)
        yield split, o.get("c_id") or name, "document", o.get("content"), {"domain": o.get("domain"), "source": o.get("source_spec")}


def ds71795(d):
    for split, name, read in members(d, "label"):
        o = jload(read, d.name)
        hint = {"meeting": o.get("meeting_name"), "committee": o.get("committee_name")}
        for side in ("question", "answer"):
            yield split, o.get("id") or name, side, (o.get(side) or {}).get("comment"), hint


def ds71788(d):
    for split, name, read in members(d, "source"):
        for doc in jload(read, d.name).get("data", []):
            hint = {"main": doc.get("category_main"), "middle": doc.get("category_middle"), "collection": doc.get("collection_name")}
            for para in (doc.get("corpus") or "").splitlines():
                yield split, doc.get("source_id") or name, "document", para, hint


def ds71848(d):
    for split, name, read in members(d, "source", ".csv"):
        rows = csv.reader(read().splitlines())
        next(rows, None)  # 머리글: 판결문 번호, 구분, 문장 번호, 내용
        for r in rows:
            if len(r) >= 4:
                yield split, name, "court", r[3], {"section": r[1]}


SEALED = {"71848": ds71848, "71305": utterances, "71630": ds71630, "71302": utterances, "71618": ds71618, "71791": ds71791,
          "71694": utterances, "544": ds544, "71875": ds71875, "71795": ds71795, "71788": ds71788}

PARSERS = {"86": ds86, "98": ds98, "114": ds114, "543": ds543, "558": ds558, "569": ds569, "580": ds580, "619": ds619,
           "71806": ds71806, "71807": None, "71844": consulting, "71852": consulting, "71926": consulting, "71968": ds71968}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--only", default="")
    ap.add_argument("--max-docs", type=int, default=0, help="71807 처럼 아주 큰 데이터셋에서 읽을 문서 파일 수 상한(0 은 전부)")
    ap.add_argument("--set", default="aihub", choices=("aihub", "sealed"))
    a = ap.parse_args()
    root = Path(a.root)
    out_dir = root / "sentences"
    out_dir.mkdir(exist_ok=True)
    parsers = PARSERS if a.set == "aihub" else SEALED
    stats_path = out_dir / ("stats.json" if a.set == "aihub" else f"stats-{a.set}.json")
    stats = json.loads(stats_path.read_text(encoding="utf-8")) if stats_path.exists() else {}
    for ds in (a.only.split(",") if a.only else parsers):
        d = root / a.set / ds
        gen = ds71807(d, a.max_docs) if ds == "71807" else parsers[ds](d)
        seen, n_units, n_sent, spk, splits, docs = set(), 0, 0, Counter(), Counter(), set()
        with open(out_dir / f"{a.set}-{ds}.jsonl", "w", encoding="utf-8") as out:
            for split, doc, who, unit, hint in gen:
                n_units += 1
                docs.add(doc)
                # 원본에 숫자만 든 발화가 있어 문자열로 바꾼다.
                for s in split_sentences("" if unit is None else str(unit)):
                    s = s.strip()
                    if len(s) < 4:
                        continue
                    key = hashlib.sha1(s.encode("utf-8")).hexdigest()
                    if key in seen:
                        continue  # 같은 데이터셋 안의 똑같은 문장은 한 번만
                    seen.add(key)
                    n_sent += 1
                    spk[who] += 1
                    splits[split] += 1
                    out.write(json.dumps({"uid": f"{a.set}-{ds}-{n_sent:08d}", "ds": ds, "split": split, "doc": str(doc), "spk": who,
                                          "text": s, "hint": hint}, ensure_ascii=False) + "\n")
        stats[ds] = {"repaired_files": REPAIRED[ds], "empty_files": EMPTY[ds], "unreadable_files": UNREADABLE[ds], "units": n_units, "docs": len(docs), "sentences": n_sent, "speakers": dict(spk.most_common(8)), "splits": dict(splits),
                     "max_docs": a.max_docs if ds == "71807" else 0}
        stats_path.write_text(json.dumps(stats, ensure_ascii=False, indent=1), encoding="utf-8")
        print(ds, json.dumps(stats[ds], ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
