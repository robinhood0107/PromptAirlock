# 0010. 빌드·테스트 명령

상태: 확정 (2026-10-05). fuzz preset을 2026-10-05에 더했다.

## 결정

CMake workflow preset 하나로 configure, build, test를 실행한다. Rust 시험은 ctest 안에서 `cargo test --locked`로 함께 실행한다.

| 환경 | 명령 | preset |
|---|---|---|
| Windows | `tools\win-dev.cmd cmake --workflow --preset <preset>` | win-debug, win-release, win-asan |
| Linux | `tools/wsl-dev.sh cmake --workflow --preset <preset>` | linux-gcc14, linux-clang-asan-ubsan, linux-clang-tsan |
| Linux fuzz | `tools/wsl-dev.sh cmake --workflow --preset linux-clang-fuzz` | linux-clang-fuzz |
| 공개 정책 | `node --test .github/scripts/publication-policy.test.mjs` | |

- Windows 컴파일러는 clang-cl(MSVC STL), Linux는 gcc-14와 clang-23이다.
- `tools/win-dev.cmd`는 Visual Studio 환경을 불러오고 vcpkg 경로를 복원한 뒤 명령을 실행한다.
- `linux-clang-fuzz`는 clang-23 libFuzzer와 ASan·UBSan으로 C++ core만 빌드한다(Rust Vault 빌드·시험 생략). ctest가 fuzz 대상마다 60초(`PA_FUZZ_SECONDS`) 동안 돌리고, 단위·compile-fail·property 시험도 함께 돌린다. Windows clang-cl은 libFuzzer preset을 두지 않는다.
- 시험 종류: 단위(`tests/unit/`), compile-fail(`tests/compile_fail/`, 정상 짝은 일반 빌드에서 컴파일되고 잘못된 짝은 기대한 진단으로 실패해야 통과), property(`tests/property/`, 고정 seed), core purity 검사(`tests/purity/`, core 소스의 I/O·시계·난수·정규식 금지), fuzz(`tests/fuzz/`).

## 대안

- 환경별 셸 스크립트로 단계를 나눠 실행.

## 근거

Phase 1~3에서 같은 형태로 Windows 4개, Linux 3개 preset을 실행했고 모두 통과했다.

알려진 제약

- Visual Studio의 `vcvars64.bat`는 `VCPKG_ROOT`를 Visual Studio 내장 vcpkg로 바꾼다. wrapper를 거치지 않으면 다른 vcpkg가 쓰인다.
- Windows clang-cl의 UBSan 런타임은 static CRT(/MT)용만 있어 vcpkg 동적 CRT 의존과 섞을 수 없다. UBSan과 TSan은 Linux에서 실행한다.
- Windows에서 CMake는 링커를 직접 호출하므로 ASan 런타임 라이브러리를 링크 옵션에 명시해야 한다.
- clang-23과 libstdc++ 14 조합은 `| std::ranges::to<std::vector>()` 파이프 형태를 컴파일하지 못한다. 함수 호출 형태를 쓴다.
- Windows 빌드 경로가 길면 리소스 컴파일러가 실패한다. 빌드 디렉터리는 짧게 둔다.

## 보안 영향

- sanitizer 빌드를 같은 명령 체계로 상시 실행할 수 있다.

## 변경 조건

- CI에 제품 빌드 job을 추가할 때 같은 preset을 쓴다. preset 이름을 바꾸면 이 문서를 갱신한다.
