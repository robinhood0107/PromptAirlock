# 0006. 한국어 NER과 tokenizer

상태: 확정 (2026-10-05)

## 결정

- 모델: Hugging Face `atonlee/koelectra-ko-pii-ner`, 커밋 1e75c01e707232401883cf364151bbe2e560c708의 `onnx/model.onnx`(fp32, 53.9 MiB, Apache-2.0).
- 모델 라벨 중 사람 이름과 조직만 쓴다. 전화번호, 주민등록번호 같은 형식 있는 값은 결정론 detector가 맡는다.
- tokenizer: 모델과 같은 커밋의 `tokenizer.json`을 직접 읽는 C++ WordPiece 구현. 지원하지 않는 구성이면 로드를 거부한다.
- 입력이 512 token을 넘으면 자르지 않고 오류로 거부한다. 긴 입력 분할은 NER 통합 단계에서 다룬다.
- 이름 끝 음절과 조사가 한 subword로 묶이는 경우는 받침 호응을 확인하는 후처리로 경계를 자른다.

합격 기준(합성 fixture 기준)

| 항목 | 기준 |
|---|---|
| offset 오류 | 0 |
| PERSON recall | 0.9 이상 |
| ORGANIZATION recall | 0.8 이상 |
| 256 token, CPU 1 thread p95 | 200 ms 이하(정규화, tokenize, 추론, decode 전체) |

## 대안

| 후보 | 결과 |
|---|---|
| 같은 모델 int8(14 MiB) | 기준 통과, ORG recall 0.818로 여유 없음 |
| `1T/veil-pii-ko-lite` int8 | 256 token p95 310.7 ms로 지연 기준 미달 |
| `Wismut/nym-pii-multilingual-small` int8 | ORG recall 0.364로 미달 |
| GLiNER multi v2.1 | 미측정 |

라이선스 표기가 없거나 비상업 조건이거나 ShareAlike 조건인 후보, ORG 라벨이 없는 후보, ONNX 배포본이 없는 후보는 측정하지 않았다.

## 근거

합성 fixture 60건(PERSON 75개, ORG 22개), Ryzen 7 9800X3D, ONNX Runtime 1.30.0 CPU 1 thread.

| 항목 | 값 |
|---|---|
| PERSON precision / recall | 0.935 / 0.960, 조사 후처리 후 0.961 / 0.987 |
| ORG precision / recall | 0.905 / 0.864 |
| 조사 경계 오류 | 2건에서 후처리 후 0건 |
| offset 오류 | 0 (851 token 역검증) |
| 256 token p50 / p95 | 28.6 / 32.2 ms |
| cold start | 151 ms |
| peak working set | 105 MB |
| tokenizer 일치 | 기준 구현과 360/360 |

Python이 없는 최소 PATH 환경에서 실행했다.

## 라이선스

- 모델 가중치는 Apache-2.0(모델 카드 표기)이며 배포 묶음에 포함할 수 있다. 배포 시 Apache-2.0 전문, 출처 저장소와 커밋, 저작자 표시를 넣는다.
- 학습 데이터 세 종은 CC BY 4.0이다. 가중치가 데이터의 2차적 저작물인지는 정리되지 않았으므로 데이터 저작자 표시를 함께 넣는다.
- 기반 모델(KoELECTRA-small v3)은 Hugging Face 카드에 라이선스 표기가 없고 GitHub 저장소의 Apache-2.0에 기댄다.
- 기반 모델 사전학습에 쓰인 국립국어원 모두의 말뭉치는 결과물 공개 시 사전 승인과 사용 사실 표기를 요구한다. 해당 승인 여부는 확인하지 못했다. 공개 배포 전에 확인한다.

## 보안 영향

- 탐지하지 못한 이름은 가명화되지 않는다. 잔여 검사와 기관 보호어로 보완하지만 recall이 1이 아니므로 남는 위험이 있다.
- 받침 있는 이름이 조사와 같은 글자로 끝나면(예: 이름이 "이"로 끝남) 후처리가 이름을 잘못 자를 수 있다.
- 모델 파일은 고정 커밋과 SHA-256으로 확인한다. 실행 중에 모델을 내려받지 않는다.

## 변경 조건

- 더 큰 합성 셋에서 합격 기준에 미달하면 다른 후보로 바꾼다.
- 사전학습 코퍼스 이용 조건을 확인한 결과 재배포에 문제가 있으면 바꾼다.
