// 학습용 FFI 실험: Rust cdylib 를 같은 프로세스에 올렸을 때 C++ 코드가 Rust 가 보관한 원문을 읽을 수 있음을 보인다.
// 운영 구조(별도 Vault 프로세스)의 근거 자료이며, 운영 경로에서 이 DLL 을 쓰지 않는다(spec §32.1).
#include <gtest/gtest.h>

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

extern "C" {
struct FfiStore;
FfiStore* pa_ffi_new();
std::uint64_t pa_ffi_put(FfiStore* store, const std::uint8_t* ptr, std::size_t len);
std::intptr_t pa_ffi_get(const FfiStore* store, std::uint64_t id, std::uint8_t* out, std::size_t cap);
void pa_ffi_free(FfiStore* store);
}

namespace {

constexpr std::uint8_t kMask = 0x5A;
constexpr std::size_t kCanary = 32;

// 자기 프로세스의 커밋된 private 메모리를 ReadProcessMemory 로 훑어 canary 출현 횟수를 센다.
// canary 원문은 이 함수에 넘기지 않고 kMask 로 가린 사본만 넘긴다(검색 패턴이 메모리에 남지 않게).
int count_occurrences(const std::array<std::uint8_t, kCanary>& masked) {
    constexpr SIZE_T kChunk = 1 << 20;
    auto* scratch = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, kChunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (scratch == nullptr) return -1;
    int found = 0;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    auto* addr = static_cast<std::uint8_t*>(si.lpMinimumApplicationAddress);
    auto* end = static_cast<std::uint8_t*>(si.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        auto* base = static_cast<std::uint8_t*>(mbi.BaseAddress);
        const bool readable = mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                              (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_WRITECOPY)) != 0 &&
                              (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
        if (readable && base != scratch) {
            for (SIZE_T off = 0; off < mbi.RegionSize; off += kChunk - kCanary) {
                const SIZE_T want = std::min<SIZE_T>(kChunk, mbi.RegionSize - off);
                SIZE_T got = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), base + off, scratch, want, &got) || got < kCanary) {
                    if (want <= kCanary) break;
                    continue;
                }
                for (SIZE_T i = 0; i + kCanary <= got; ++i) {
                    if ((scratch[i] ^ kMask) != masked[0]) continue;
                    bool all = true;
                    for (std::size_t k = 1; k < kCanary && all; ++k) all = (scratch[i + k] ^ kMask) == masked[k];
                    if (all && (off == 0 || i > 0)) ++found;  // 겹친 구간의 첫 위치는 이전 조각에서 셌다
                }
                SecureZeroMemory(scratch, got);
                if (want < kChunk) break;
            }
        }
        addr = base + mbi.RegionSize;
    }
    VirtualFree(scratch, 0, MEM_RELEASE);
    return found;
}

TEST(FfiLearning, Roundtrip) {
    FfiStore* s = pa_ffi_new();
    const std::uint8_t v[] = {'s', 'y', 'n', 't', 'h'};
    const auto id = pa_ffi_put(s, v, sizeof(v));
    std::array<std::uint8_t, 16> out{};
    EXPECT_EQ(pa_ffi_get(s, id, out.data(), out.size()), 5);
    EXPECT_EQ(pa_ffi_get(s, id + 100, out.data(), out.size()), -1);
    pa_ffi_free(s);
}

TEST(FfiLearning, SameAddressSpaceExposesRustHeldSecret) {
    std::array<std::uint8_t, kCanary> canary{};
    std::array<std::uint8_t, kCanary> masked{};
    std::random_device rd;
    for (std::size_t i = 0; i < kCanary; ++i) {
        canary[i] = static_cast<std::uint8_t>(rd());
        masked[i] = static_cast<std::uint8_t>(canary[i] ^ kMask);
    }
    FfiStore* s = pa_ffi_new();
    pa_ffi_put(s, canary.data(), canary.size());
    SecureZeroMemory(canary.data(), canary.size());

    // C++ 쪽 사본을 지운 뒤에도, 같은 주소 공간의 아무 C++ 코드(버그·취약점 포함)가 Rust 소유 원문을 읽을 수 있다.
    const int while_held = count_occurrences(masked);
    std::printf("ffi canary occurrences while Rust holds it: %d\n", while_held);
    EXPECT_GE(while_held, 1);

    pa_ffi_free(s);
    const int after_free = count_occurrences(masked);
    std::printf("ffi canary occurrences after pa_ffi_free (zeroize): %d\n", after_free);
    // Rust 소유 사본은 zeroize 로 사라져 개수가 줄어야 한다. 0 이 아닐 수 있다: ASan 빌드에서는 C++ 쪽
    // 다른 사본(스택/fake stack 등)이 1개 관찰됐다. zeroize 가 "다른 사본 없음"을 증명하지 않는다는 spec §31 의 사례다.
    EXPECT_LT(after_free, while_held);
}

}  // namespace
