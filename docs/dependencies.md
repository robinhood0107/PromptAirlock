# 외부 의존성과 라이선스

이 저장소가 쓰는 외부 라이브러리와 그 판, 라이선스, 연결 방식을 적습니다. 프로젝트 라이선스(AGPL-3.0-only)와 함께 배포할 수 있는지를 의존성을 들일 때 확인했고, 새 의존성을 더할 때마다 이 표에 한 줄씩 더합니다.

- C++ 의존성은 vcpkg manifest(`vcpkg.json`)와 baseline `19780d9cdf84d0944cf9a318666703b89ab6629c` 로 판을 고정합니다(ADR 0005).
- Rust 의존성은 `vault/Cargo.lock` 으로 판과 해시를 고정하고 `--locked` 로만 빌드합니다.
- 배포 묶음을 만들 때(ADR 0012) 각 라이브러리의 저작권·라이선스 고지를 함께 넣습니다. Apache-2.0 라이브러리는 NOTICE 내용도 넣습니다.
- OpenSSL 3 은 Apache-2.0 이라 AGPL-3.0 과 함께 배포할 수 있습니다(OpenSSL 1.x 의 이전 라이선스 문제는 3.0 부터 없습니다).

## C++ (vcpkg)

| 라이브러리 | 판 | 라이선스 | 쓰는 곳 | 연결 방식 |
|---|---|---|---|---|
| utf8proc | 2.12.0 | MIT | `src/detect`(NFKC 정규화) | Windows DLL, Linux 정적 |
| protobuf(libprotobuf, protoc) | 6.33.4 | BSD-3-Clause | `src/vault_client`(Vault 통신 형식), protoc 는 빌드 때 C++·Rust 코드 생성만 | Windows DLL, Linux 정적 |
| abseil(protobuf 가 씀) | 20260107.1 | Apache-2.0 | protobuf 내부 | Windows DLL, Linux 정적 |
| utf8-range(protobuf 가 씀) | 6.33.4 | MIT | protobuf 내부 | 정적 |
| boost-asio(와 Boost 하위 라이브러리) | 1.92.0 | BSL-1.0 | `src/vault_client`(Named Pipe·UDS 입출력) | 대부분 헤더, 일부 하위 라이브러리 링크 |
| boost-beast | 1.92.0 | BSL-1.0 | `src/gateway`(HTTPS 서버) | 헤더만 |
| OpenSSL | 3.6.5 | Apache-2.0 | `src/tls`(TLS 협상 범위, ADR 0014), `src/gateway`(HTTPS 입출력) | Windows DLL, Linux 정적 |
| nlohmann-json | 3.12.0 | MIT | `src/ner`(tokenizer.json 읽기), `src/gateway`(설정·오류 응답, ADR 0020), `src/audit`(감사 기록) | 헤더만 |
| gtest | 1.18.0 | BSD-3-Clause | 시험만 | 배포하지 않음 |
| sentencepiece | 0.2.1 | Apache-2.0 | `tests/measure` 의 문장 판별 후보 측정만(vcpkg 기능 `sentence-spike`, 기본 빌드에 없음, ADR 0022) | 배포하지 않음(정적, 측정 도구에만) |

## 공식 배포본과 모델(CMake 가 고정 해시로 받음)

vcpkg 포트가 아니라 고정 주소에서 받아 SHA-256 을 확인한 뒤에만 씁니다(ADR 0005, 0006). 실행 중에는 내려받지 않습니다.

| 이름 | 판 | 라이선스 | 쓰는 곳 | 연결 방식 |
|---|---|---|---|---|
| ONNX Runtime(공식 배포본, Windows x64·Linux x64) | 1.30.0 | MIT | `src/ner`(NER 추론, CPU) | 공유 라이브러리(`cmake/OnnxRuntime.cmake`) |
| NER 모델 `atonlee/koelectra-ko-pii-ner`(model.onnx fp32, tokenizer.json, config.json) | 커밋 `1e75c01e707232401883cf364151bbe2e560c708` | Apache-2.0 | `src/ner`(사람·기관 이름 찾기) | 데이터 파일, 실행 파일 옆 `models/ner/`(`cmake/NerModel.cmake`) |

- 배포 묶음에는 ONNX Runtime 의 ThirdPartyNotices 와 모델 출처·저작자 고지를 함께 넣습니다. 모델 학습 데이터와 백본 가중치에 관한 남은 확인은 배포 전에 닫습니다.

## 오프라인 학습 도구(Python, `training/`)

문장 판별기 실험과 학습에만 씁니다(결정 #174). 제품 빌드·CI 빌드·런타임·배포 묶음에는 들어가지 않습니다. 판은 `training/requirements.txt` 로 고정합니다.

| 패키지 | 판 | 라이선스 | 쓰는 곳 |
|---|---|---|---|
| numpy | 2.5.1 | BSD-3-Clause | 분류기 학습, 평가 계산 |
| onnxruntime | 1.30.0 | MIT | 후보 모델 문장 벡터(C++ 과 같은 판) |
| tokenizers | 0.22.2 | Apache-2.0 | 후보 모델 tokenizer.json 읽기 |

## Rust Vault(`vault/crates/prompt-airlock-vault`)

직접 쓰는 crate

| crate | 판 | 라이선스 | 쓰는 곳 | 연결 방식 |
|---|---|---|---|---|
| tokio | 1.53.2 | MIT | 비동기 입출력(Named Pipe, UDS) | Vault 실행 파일에 정적 |
| prost | 0.14.4 | Apache-2.0 | 통신 형식(protobuf) 읽기·쓰기 | 정적 |
| bytes | 1.12.1 | MIT | 프레임 버퍼 | 정적 |
| zeroize | 1.9.0 | Apache-2.0 OR MIT | 원문·비밀값 지우기, 지우는 할당기 | 정적 |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | token·범위 id·비밀값 난수(운영체제 CSPRNG) | 정적 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 | Windows 파이프 보안 설명자(현재 사용자 DACL) | 정적(Windows) |
| prost-build | 0.14.4 | Apache-2.0 | 빌드 때 `proto/vault_v1.proto` 에서 Rust 코드 생성 | 실행 파일에 들어가지 않음 |

간접 crate

- 실행 파일에 들어가는 것: mio 1.2.4(MIT), socket2 0.6.5(MIT OR Apache-2.0), pin-project-lite 0.2.17(Apache-2.0 OR MIT), cfg-if 1.0.5(MIT OR Apache-2.0), libc 0.2.190(MIT OR Apache-2.0, Linux), windows-link 0.2.1(MIT OR Apache-2.0, Windows).
- 빌드 때만 쓰고 실행 파일에 들어가지 않는 것: prost-derive, prost-types, tokio-macros, proc-macro2, quote, syn, unicode-ident, regex 와 그 하위 crate, petgraph, itertools, indexmap, hashbrown, multimap, heck, prettyplease, tempfile, either, log, once_cell, fixedbitset, equivalent, foldhash, fastrand, anyhow. 라이선스는 모두 MIT, Apache-2.0, 또는 그 둘 가운데 선택이고, unicode-ident 는 Unicode-3.0 이 더해지고 foldhash 는 Zlib 입니다.
- 정확한 판과 해시는 `vault/Cargo.lock` 이 원본입니다.

## 판단

- 위 라이선스(MIT, BSD-3-Clause, BSL-1.0, Apache-2.0, Zlib, Unicode-3.0)는 모두 AGPL-3.0 프로젝트와 함께 배포할 수 있는 허용형 라이선스입니다.
- 강한 copyleft 라이선스(GPL, LGPL 단독)를 요구하는 의존성은 없습니다. 선택지에 LGPL 이 들어 있는 crate(r-efi)는 지원 대상 플랫폼에서 컴파일되지 않아 lock 에만 있습니다.
