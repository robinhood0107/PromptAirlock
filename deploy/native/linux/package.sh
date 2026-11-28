#!/usr/bin/env bash
set -euo pipefail

repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
build_root="${1:?}"
destination="${2:?}"
build_root="$(cd -- "$build_root" && pwd)"
app_source="$build_root/apps/prompt-airlock"
vault_source="$build_root/cargo/release/prompt-airlock-vault"
model_source="$build_root/models/ner"

test -x "$app_source/prompt-airlock"
test -x "$app_source/prompt-airlock-extract"
test -x "$vault_source"
test -f "$model_source/model.onnx"
test -f "$build_root/CMakeCache.txt"

mkdir -p -- "$destination"
test -z "$(find "$destination" -mindepth 1 -print -quit)"
mkdir -p -- "$destination/bin" "$destination/lib" "$destination/libexec" "$destination/share/models/ner" "$destination/share/licenses"
install -m 0755 -- "$app_source/prompt-airlock" "$destination/bin/prompt-airlock"
install -m 0755 -- "$app_source/prompt-airlock-extract" "$destination/bin/prompt-airlock-extract"
install -m 0755 -- "$vault_source" "$destination/libexec/prompt-airlock-vault"
cp -a -- "$model_source/." "$destination/share/models/ner/"
install -m 0644 -- "$repo/LICENSE" "$destination/share/licenses/PromptAirlock-LICENSE"
install -m 0755 -- "$repo/deploy/native/linux/start.sh" "$destination/start.sh"
install -m 0644 -- "$repo/deploy/native/linux/prompt-airlock.service" "$destination/prompt-airlock.service"

installed="$(sed -n 's/^VCPKG_INSTALLED_DIR:PATH=//p' "$build_root/CMakeCache.txt" | head -n 1)"
triplet="$(sed -n 's/^VCPKG_TARGET_TRIPLET:STRING=//p' "$build_root/CMakeCache.txt" | head -n 1)"
ort_version="$(sed -n 's/^set(PA_ORT_VERSION \(.*\))$/\1/p' "$repo/cmake/OnnxRuntime.cmake" | head -n 1)"
test -n "$installed"
test -n "$triplet"
test -n "$ort_version"
case "$installed" in
  /*) ;;
  *) installed="$build_root/$installed" ;;
esac
test -d "$installed/$triplet/share"
test -d "$installed/$triplet/lib"
for library in "$installed/$triplet"/lib/*.so*; do
  test -e "$library" || continue
  cp -a -- "$library" "$destination/lib/"
done
ort_root="$repo/_deps/onnxruntime-linux-x64-$ort_version"
test -f "$ort_root/lib/libonnxruntime.so.$ort_version"
test -f "$ort_root/LICENSE"
test -f "$ort_root/ThirdPartyNotices.txt"
for library in "$ort_root"/lib/*.so*; do
  test -e "$library" || continue
  cp -L -- "$library" "$destination/lib/$(basename "$library")"
done
mkdir -p -- "$destination/share/licenses/onnxruntime"
install -m 0644 -- "$ort_root/LICENSE" "$ort_root/ThirdPartyNotices.txt" "$destination/share/licenses/onnxruntime/"
while IFS= read -r -d '' copyright; do
  package="$(basename "$(dirname "$copyright")")"
  mkdir -p -- "$destination/share/licenses/vcpkg/$package"
  install -m 0644 -- "$copyright" "$destination/share/licenses/vcpkg/$package/copyright"
done < <(find "$installed/$triplet/share" -mindepth 2 -maxdepth 2 -type f -name copyright -print0)

(
  cd -- "$destination"
  find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum > manifest.sha256
)
