#!/usr/bin/env bash
# WSL gcc-14 / clang-23 환경 점검. 사용법: wsl-env-check.sh <출력 디렉터리>
set -u
out="${1:-$(dirname "$0")/out-wsl}"
mkdir -p "$out"
src="$(dirname "$0")/expected_smoke.cpp"

echo "== versions"
gcc-14 --version | head -1
clang++-23 --version | head -1 || clang-23 --version | head -1
cmake --version | head -1
ninja --version
cargo --version
echo "VCPKG_ROOT=${VCPKG_ROOT:-unset}"

echo "== gcc-14"
g++-14 -std=c++23 -O2 -Wall -Wextra "$src" -o "$out/smoke-gcc" -pthread && "$out/smoke-gcc"
echo "exit=$?"

cxx=clang++-23
command -v "$cxx" >/dev/null || cxx="clang-23 -x c++ -lstdc++"
echo "== clang-23 asan+ubsan"
$cxx -std=c++23 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined "$src" -o "$out/smoke-asan" -pthread && "$out/smoke-asan"
echo "normal-exit=$?"
"$out/smoke-asan" --uaf 2> "$out/asan-uaf.txt"; grep -q heap-use-after-free "$out/asan-uaf.txt" && echo asan-detected=yes || echo asan-detected=no
"$out/smoke-asan" --overflow x 2> "$out/ubsan-overflow.txt"; grep -q "signed integer overflow" "$out/ubsan-overflow.txt" && echo ubsan-detected=yes || echo ubsan-detected=no

echo "== clang-23 tsan"
$cxx -std=c++23 -O1 -g -fsanitize=thread "$src" -o "$out/smoke-tsan" -pthread && "$out/smoke-tsan"
echo "normal-exit=$?"
"$out/smoke-tsan" --race 2> "$out/tsan-race.txt"; grep -q "data race" "$out/tsan-race.txt" && echo tsan-detected=yes || echo tsan-detected=no
