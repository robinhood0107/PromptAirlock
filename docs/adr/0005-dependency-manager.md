# 0005. 의존성 관리

상태: 확정 (2026-10-05)

## 결정

- C++ 라이브러리는 vcpkg manifest 모드로 받는다. `builtin-baseline`은 19780d9cdf84d0944cf9a318666703b89ab6629c로 고정한다.
- triplet은 Windows `x64-windows`, Linux `x64-linux`.
- ONNX Runtime은 vcpkg 포트(소스 빌드)가 아니라 공식 배포 바이너리 1.30.0을 SHA-256 확인 후 쓴다.
- Rust 의존성은 `Cargo.lock`으로 고정하고 빌드는 `--locked`로 한다.
- 시스템 도구(LLVM, Visual Studio, CMake, Rust toolchain)는 저장소가 설치하지 않는다.

## 대안

- Conan 2.

## 근거

- 빌드 디렉터리를 지운 뒤 다시 빌드하면 62개 패키지를 binary cache에서 3.6초 만에 복원했고 전체 workflow는 33초였다.
- Windows와 Linux에서 같은 baseline으로 같은 버전이 설치됐다.
- Conan은 패키지 recipe가 Python 코드다. 이 프로젝트는 Python을 쓰지 않는다. Conan은 설치하지 않고 공식 배포 정보로 비교했다.

## 보안 영향

- 라이브러리 버전이 저장소 커밋으로 고정되고 소스에서 빌드된다.
- ONNX Runtime 바이너리는 GitHub release에 게시된 SHA-256과 대조한다.

## 변경 조건

- 필요한 라이브러리가 vcpkg에 없거나 바이너리 배포가 필요해지면 다시 검토한다.
- baseline을 올릴 때는 전체 시험과 라이선스 표를 다시 확인한다.
