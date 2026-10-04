# 0004. HTTP stack

상태: 확정 (2026-10-05)

## 결정

Boost.Asio와 Boost.Beast 1.92.0, TLS는 OpenSSL 3.6.5. 비동기 처리는 C++20 coroutine으로 한다.

## 대안

- Drogon 1.9.13.

## 근거

같은 시나리오 세 가지(TLS 왕복, 신뢰하지 않는 인증서 거부, 응답 지연 시 timeout)를 두 라이브러리로 구현해 모두 통과했다.

| 항목 | Beast | Drogon |
|---|---|---|
| 시나리오 코드(빈 줄·주석 제외) | 126줄 | 90줄 |
| 추가 패키지 | 없음 | zlib, c-ares, trantor, jsoncpp, brotli, drogon |
| 설치 크기(vcpkg_installed) | 219 MB | 355 MB |
| 배포 DLL | OpenSSL 2개 | OpenSSL 2개와 추가 DLL 8개(3.3 MB) |
| 서버 인증서 지정 | 메모리 버퍼 | 파일 경로만 |
| 실행 상태 | 사용자가 소유 | 프로세스 전역 단일 app 객체, 한 프로세스에서 한 번만 실행 |

## 보안 영향

- 인증서 검증, host name 확인, timeout, 취소를 요청 단위로 직접 제어한다.
- 전역 상태가 없어 요청별 상태를 분리하기 쉽다.
- 객체 수명 관리를 직접 해야 하므로 수명 오류 위험이 있다. ASan과 TSan 시험을 상시 실행해 보완한다.

## 변경 조건

- streaming 응답(SSE) 처리를 포함한 HTTP 코드가 C++ 코드의 큰 비중을 차지하게 되면 상위 framework를 다시 검토한다.
