# 0009. 런타임 DLL/SO 배치

상태: 확정 (2026-10-05)

## 결정

- 외부 라이브러리는 load-time dynamic linking으로 쓴다. run-time 로딩(LoadLibrary, dlopen)은 쓰지 않는다.
- 필요한 DLL은 빌드 시 실행 파일 옆에 둔다.
  - vcpkg 패키지 DLL: vcpkg toolchain이 복사한다.
  - ONNX Runtime 같은 수동 IMPORTED target: POST_BUILD에서 `$<TARGET_RUNTIME_DLLS>`를 복사한다. 목록이 비면 아무것도 하지 않는다.
  - ASan 빌드: clang ASan 런타임 DLL을 복사한다.
- 전역 PATH를 바꾸지 않는다.
- ONNX Runtime은 CPU 실행에 `onnxruntime.dll`만 둔다.
- Linux 배포 묶음의 라이브러리 검색 경로는 실행 파일 기준 상대 경로($ORIGIN)로 한다. Linux 실기 검증은 아직 하지 않았다.

## 대안

- 정적 링크.
- 전역 PATH나 시스템 디렉터리에 설치.

## 근거

- 빌드 디렉터리를 지우고 다시 빌드한 뒤 PATH를 `C:\Windows\System32`로 줄이고 다른 작업 디렉터리에서 실행해도 ONNX Runtime 시험과 NER 측정이 통과했다.
- `onnxruntime_providers_shared.dll` 없이 CPU 추론이 동작했다.

## 보안 영향

- DLL 검색이 실행 파일 디렉터리에서 끝나므로 PATH를 이용한 DLL 바꿔치기 위험이 줄어든다.
- 배포 묶음에 ONNX Runtime ThirdPartyNotices와 OpenSSL 라이선스·고지를 넣어야 한다.

## 변경 조건

- Linux 실기 검증에서 $ORIGIN 방식에 문제가 있으면 다시 정한다.
