# 제3자 고지

Prompt Airlock 배포 묶음에 함께 들어가는 다른 사람의 라이브러리, 모델, 데이터와 그 라이선스입니다. 판과 쓰는 곳은 [docs/dependencies.md](docs/dependencies.md)가 원본이고, 이 문서는 고지 의무를 지키기 위한 목록입니다.

배포 묶음(ADR 0012, 0024)을 만들 때 각 항목의 라이선스 전문과 저작권 표시를 그 판의 원본 파일에서 그대로 옮겨 이 문서 뒤에 붙입니다. Apache-2.0 항목은 NOTICE 파일이 있으면 그 내용도 붙입니다. 시험에만 쓰는 것(gtest, sentencepiece)과 빌드 때만 쓰는 것(protoc, prost-build 와 그 하위 crate)은 배포 묶음에 들어가지 않아 여기에 적지 않습니다.

## 라이브러리

| 이름 | 판 | 라이선스 | 출처 |
|---|---|---|---|
| utf8proc | 2.12.0 | MIT | https://github.com/JuliaStrings/utf8proc |
| Protocol Buffers(libprotobuf) | 6.33.4 | BSD-3-Clause | https://github.com/protocolbuffers/protobuf |
| utf8_range(protobuf 안) | 6.33.4 | MIT | https://github.com/protocolbuffers/protobuf |
| Abseil | 20260107.1 | Apache-2.0 | https://github.com/abseil/abseil-cpp |
| Boost(Asio, Beast 와 하위 라이브러리) | 1.92.0 | BSL-1.0 | https://www.boost.org |
| OpenSSL | 3.6.5 | Apache-2.0 | https://www.openssl.org |
| JSON for Modern C++(nlohmann-json) | 3.12.0 | MIT | https://github.com/nlohmann/json |
| ONNX Runtime(공식 배포본) | 1.30.0 | MIT, 배포본의 ThirdPartyNotices.txt 를 함께 넣음 | https://github.com/microsoft/onnxruntime |
| tokio | 1.53.2 | MIT | https://github.com/tokio-rs/tokio |
| prost | 0.14.4 | Apache-2.0 | https://github.com/tokio-rs/prost |
| bytes | 1.12.1 | MIT | https://github.com/tokio-rs/bytes |
| zeroize | 1.9.0 | Apache-2.0 OR MIT | https://github.com/RustCrypto/utils |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | https://github.com/rust-random/getrandom |
| windows-sys(Windows) | 0.61.2 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |
| mio | 1.2.4 | MIT | https://github.com/tokio-rs/mio |
| socket2 | 0.6.5 | MIT OR Apache-2.0 | https://github.com/rust-lang/socket2 |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT | https://github.com/taiki-e/pin-project-lite |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | https://github.com/rust-lang/cfg-if |
| libc(Linux) | 0.2.190 | MIT OR Apache-2.0 | https://github.com/rust-lang/libc |
| windows-link(Windows) | 0.2.1 | MIT OR Apache-2.0 | https://github.com/microsoft/windows-rs |

## 모델

### NER 모델 koelectra-ko-pii-ner

- 파일: `model.onnx`(fp32), `tokenizer.json`, `config.json`. 바꾸지 않고 그대로 넣습니다.
- 출처: https://huggingface.co/atonlee/koelectra-ko-pii-ner, 커밋 `1e75c01e707232401883cf364151bbe2e560c708`
- 라이선스: Apache-2.0
- 바탕 모델: KoELECTRA-small-v3 discriminator(https://github.com/monologg/KoELECTRA, Apache-2.0). KoELECTRA-v3 사전학습에는 국립국어원 모두의 말뭉치가 쓰였습니다.
- 미세조정 데이터(CC BY 4.0, 모델 제작자가 밝힌 출처)
  - BCCard/pii-masking-openpii-finance(https://huggingface.co/datasets/BCCard/pii-masking-openpii-finance), CC BY 4.0. 원천 ai4privacy/pii-masking-openpii-1.5m(https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1.5m), CC BY 4.0.
  - townboy/korean-pii-dataset(https://huggingface.co/datasets/townboy/korean-pii-dataset), CC BY 4.0.
  - CC BY 4.0 전문: https://creativecommons.org/licenses/by/4.0/

이 저장소는 위 데이터를 받거나 다시 배포하지 않습니다. 모델 가중치만 씁니다.

## 함께 넣지 않는 것

- 문장 판별기 모델(ADR 0022, 0023)은 기본 꺼짐이고(ADR 0025) 배포 묶음에 넣지 않습니다. 설치하는 쪽이 따로 둔 파일을 설정으로 켤 때만 씁니다.
- 판별기 학습과 평가에 쓴 데이터셋은 저장소와 배포 묶음 어디에도 넣지 않습니다.
