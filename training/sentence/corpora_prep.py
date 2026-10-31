# 말뭉치 정리(Phase 7.8-1, 결정 #182): 출처 원장, 라벨링·원천 쌍 검증, 압축 풀기, 검증된 zip 지우기.
# 사용: python corpora_prep.py <말뭉치 폴더(corpora)> [--extract] [--delete]
#   (인자 없음) 출처 원장 MANIFEST.json 과 쌍 검증만. 원문은 화면에 내지 않고 개수만 낸다.
#   --extract   텍스트 파일을 aihub/<번호>/extracted/{label,source}/<zip 이름>/ 아래에 푼다. 음성(.m4a, .mp3)은 풀지 않는다.
#               71807 원천(메타데이터 약 299만 개의 작은 JSON)은 파일로 풀지 않고 같은 내용을 문서 한 줄씩 담은
#               source-documents.jsonl 하나로 옮긴다(파일 이름 포함, 내용 그대로).
#   --delete    풀어 둔 내용이 zip 과 같다고 확인된 zip(개수·크기 일치)과 쓰지 않는 음성 zip 을 지운다. 지우기 전 해시는 원장에 남는다.
import argparse
import base64
import hashlib
import json
import re
import zipfile
from collections import Counter
from pathlib import Path

# 출처 표시: 이용정책은 "한국지능정보사회진흥원의 사업결과임" 을 2차적 저작물에도 밝히도록 한다.
DATASETS = {
    "86": ("감성 대화 말뭉치", 2020), "98": ("민원(콜센터) 질의-응답 데이터", 2020), "114": ("한국어 SNS", 2020),
    "543": ("주제별 텍스트 일상 대화 데이터", 2021), "558": ("텍스트 윤리검증 데이터", 2021), "569": ("행정 문서 대상 기계독해 데이터", 2021),
    "580": ("법률/규정 (판결서, 약관 등) 텍스트 분석 데이터", 2021), "619": ("민원 업무 자동화 인공지능 언어 데이터", 2021),
    "71806": ("심리상담 데이터", 2024), "71807": ("컴플라이언스 데이터", 2024), "71844": ("민간 민원 상담 LLM 사전학습 및 Instruction Tuning 데이터", 2024),
    "71852": ("공공 민원 상담 LLM 사전학습 및 Instruction Tuning 데이터", 2024), "71926": ("금융분야 고객상담 데이터", 2025),
    "71968": ("판결서 익명처리 데이터", 2025),
}
AUDIO = (".m4a", ".mp3", ".wav")


def fixname(info):
    if info.flag_bits & 0x800:
        return info.filename
    try:
        return info.filename.encode("cp437").decode("cp949")
    except UnicodeError:
        return info.filename


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    return h.hexdigest()


def kind_of(path):
    p = path.as_posix()
    return "label" if ("라벨" in p or "/TL" in p or "/VL" in p) else "source"


def split_of(path):
    p = path.as_posix()
    return "valid" if ("Validation" in p or "/VL" in p or "/VS" in p) else "train"


def pair_key(ds, kind, name, read):
    """라벨링 파일과 원천 파일을 잇는 열쇠. 데이터셋마다 이름 규칙이 다르다."""
    stem = Path(name).stem
    if ds == "558":
        return stem.removesuffix("_aihub")
    if ds == "569":
        return re.sub(r"^[TV][LS]_", "", stem)
    if ds == "71806":
        return re.sub(r"^(label|resource)_", "", stem)
    if ds == "71926" and kind == "label":
        return re.sub(r"_\d{3}$", "", stem)
    if ds == "619":  # 파일 이름에 문서 수가 붙어 있어 이름으로는 맞출 수 없다. 문서 번호(라벨은 "번호-변형")로 맞춘다
        o = json.loads(read())
        return [d["id"].split("-")[0] for d in o["documents"]] if kind == "label" else [d["id"] for d in o]
    if ds == "71807":
        return json.loads(read())["info"][0]["document_id"] if kind == "label" else stem
    if ds in ("71844", "71852"):
        if kind == "label":
            return stem.split("_")[2]
        return str(json.loads(read())[0]["source_id"])
    return stem


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--delete", action="store_true")
    a = ap.parse_args()
    root = Path(a.root)
    manifest_path = root / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    for ds, (name, year) in DATASETS.items():
        d = root / "aihub" / ds
        entry = manifest.setdefault(ds, {"name": name, "year": year, "page": f"https://www.aihub.or.kr/aihubdata/data/view.do?dataSetSn={ds}",
                                          "attribution": f"이 결과물은 한국지능정보사회진흥원(NIA)의 사업결과인 「{name}」({year})을 활용하였습니다.",
                                          "zips": {}})
        if not any(d.rglob("*.zip")):
            print(ds, name, "zip 이 없어 지난 쌍 검증 기록을 그대로 둔다", flush=True)
            continue
        keys = {"label": Counter(), "source": Counter()}
        for z in sorted(d.rglob("*.zip")):
            rel = z.relative_to(root).as_posix()
            info = entry["zips"].get(rel) or {"bytes": z.stat().st_size, "sha256": sha256(z), "kind": kind_of(z), "split": split_of(z)}
            with zipfile.ZipFile(z) as zf:
                members = [i for i in zf.infolist() if not i.is_dir()]
                info["members"] = len(members)
                info["member_bytes"] = sum(i.file_size for i in members)
                info["audio"] = sum(fixname(i).lower().endswith(AUDIO) for i in members)
                for i in members:
                    nm = fixname(i)
                    if nm.lower().endswith(AUDIO) or ds in ("98", "114", "86"):
                        continue  # 98 원천은 음성, 114 는 라벨만, 86 은 파일 하나짜리 짝(이름이 같음)이라 쌍 검사를 하지 않는다
                    if ds == "71807" and info["kind"] == "source" and "메타데이터" not in nm:
                        continue
                    k = pair_key(ds, info["kind"], nm, lambda i=i: zf.read(i).decode("utf-8-sig", "replace"))
                    keys[info["kind"]].update(k if isinstance(k, list) else [k])
            entry["zips"][rel] = info
        lk, sk = set(keys["label"]), set(keys["source"])
        entry["pairs"] = {"label_keys": len(lk), "source_keys": len(sk), "both": len(lk & sk), "label_only": len(lk - sk), "source_only": len(sk - lk)}
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
        print(ds, name, f"zips={len(entry['zips'])}", json.dumps(entry["pairs"], ensure_ascii=False), flush=True)
    if a.extract:
        extract(root, manifest)
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    if a.delete:
        delete(root, manifest)
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")


def extract(root, manifest):
    for ds, entry in manifest.items():
        for rel, info in entry["zips"].items():
            z = root / rel
            if not z.exists() or info.get("extracted"):
                continue
            if info["audio"] == info["members"]:
                info["extracted"] = {"skipped": "audio"}
                continue
            dest = root / "aihub" / ds / "extracted" / info["kind"] / Path(rel).stem
            n, total = 0, 0
            with zipfile.ZipFile(z) as zf:
                if ds == "71807" and info["kind"] == "source":
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with open(dest.with_suffix(".source-documents.jsonl"), "w", encoding="utf-8") as out:
                        for i in zf.infolist():
                            if i.is_dir():
                                continue
                            raw = zf.read(i)
                            try:  # 원본 바이트를 잃지 않도록, UTF-8 이 아니면 base64 로 그대로 둔다
                                row = {"file": fixname(i), "content": raw.decode("utf-8")}
                            except UnicodeDecodeError:
                                row = {"file": fixname(i), "content_b64": base64.b64encode(raw).decode("ascii")}
                            out.write(json.dumps(row, ensure_ascii=False) + "\n")
                            n += 1
                            total += i.file_size
                else:
                    for i in zf.infolist():
                        nm = fixname(i)
                        if i.is_dir() or nm.lower().endswith(AUDIO):
                            continue
                        # 71806 처럼 이름이 "/" 로 시작하는 zip 이 있다. 앞의 경로 구분자를 떼고, ".." 로 폴더 밖을 가리키면 거부한다.
                        rel_name = nm.lstrip("/\\")
                        if ".." in Path(rel_name).parts:
                            raise ValueError(f"zip 안 경로가 폴더 밖을 가리킨다: {rel}")
                        target = dest / rel_name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(zf.read(i))
                        n += 1
                        total += i.file_size
            info["extracted"] = {"path": dest.relative_to(root).as_posix(), "files": n, "bytes": total}
            print("extracted", rel, n, flush=True)


def delete(root, manifest):
    for ds, entry in manifest.items():
        for rel, info in entry["zips"].items():
            z = root / rel
            ex = info.get("extracted") or {}
            text_members = info["members"] - info["audio"]
            # 음성만 든 zip 은 쓰지 않으므로 지운다. 텍스트 zip 은 푼 파일 수와 크기가 zip 과 같을 때만 지운다.
            ok = ex.get("skipped") == "audio" or (ex.get("files") == text_members and (info["audio"] > 0 or ex.get("bytes") == info["member_bytes"]))
            if z.exists() and ok:
                z.unlink()
                info["deleted"] = True
            elif z.exists():
                print("keep (not verified)", rel, ex, text_members)


if __name__ == "__main__":
    main()
