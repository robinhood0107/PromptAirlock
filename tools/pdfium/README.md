# PDFium 빌드(결정 #229)

추출 실행 파일의 PDF 글자 뽑기에 쓰는 PDFium 을 공식 소스에서 판 고정으로 빌드한다. 저장소 밖 캐시에서 돌리며,
depot_tools 의 Python 은 이 빌드에만 쓴다(제품 빌드·CI 에는 들어가지 않음).

| 단계 | Linux(WSL) |
|---|---|
| 1. 소스 받기(약 5 GB) | `bash tools/pdfium/fetch-linux.sh` |
| 2. 빌드 | `bash tools/pdfium/build-linux.sh` |
| 3. 묶기 | `bash tools/pdfium/package-linux.sh` → `~/.cache/prompt-airlock/pdfium/pkg/linux-x64` |
| 4. 우리 빌드에 넘김 | `cmake --preset linux-gcc14 -DPA_PDFIUM_DIR=<묶음 폴더>` |

- 판: `b75764a1def138ff0f308c637865f195774ccdc4`. 라이브러리 SHA-256 은 `cmake/Pdfium.cmake` 에 고정한다(다르면 설정 실패).
- 빌드 설정(`build-linux.sh`): V8·XFA·Skia 끔, 완전한 정적 라이브러리, 시스템 C++ 표준 라이브러리, PartitionAlloc·malloc 대체 끔(추출기의 주소 공간 제한 1 GiB 와 부딪힘), Chromium 빌드 설정의 ELF CREL 한 줄 삭제(GNU ld 가 읽지 못함). PDFium 코드는 바꾸지 않는다.
- 함께 링크되는 코드와 라이선스는 THIRD_PARTY_NOTICES.md 와 #231.
