# 모든 C++ 타깃이 공유하는 경고·sanitizer 옵션. 타깃은 pa_options 를 PRIVATE 로 링크한다.
set(PA_SANITIZE "" CACHE STRING "sanitizer 목록: address / address,undefined / thread")

add_library(pa_options INTERFACE)
if(MSVC)
  target_compile_options(pa_options INTERFACE /W4 /permissive- /EHsc /utf-8)
  target_compile_definitions(pa_options INTERFACE _WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  target_compile_options(pa_options INTERFACE -Wall -Wextra -Wpedantic)
endif()

if(PA_SANITIZE)
  if(MSVC)
    # Windows 는 ASan 만 지원한다. UBSan 런타임은 /MT 전용이라 vcpkg 동적 CRT 와 섞을 수 없다.
    if(NOT PA_SANITIZE STREQUAL "address")
      message(FATAL_ERROR "Windows 에서는 PA_SANITIZE=address 만 지원한다.")
    endif()
    # CMake 은 lld-link 를 직접 부르므로 ASan 런타임 라이브러리를 명시한다.
    execute_process(COMMAND "${CMAKE_CXX_COMPILER}" /clang:-print-resource-dir
                    OUTPUT_VARIABLE PA_CLANG_RESOURCE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(PA_CLANG_RT_DIR "${PA_CLANG_RESOURCE_DIR}/lib/windows")
    target_compile_options(pa_options INTERFACE -fsanitize=address /Zi)
    target_link_options(pa_options INTERFACE
      "/LIBPATH:${PA_CLANG_RT_DIR}" /INCREMENTAL:NO
      clang_rt.asan_dynamic-x86_64.lib
      /wholearchive:clang_rt.asan_dynamic_runtime_thunk-x86_64.lib)
    set(PA_ASAN_DLL "${PA_CLANG_RT_DIR}/clang_rt.asan_dynamic-x86_64.dll")
  else()
    target_compile_options(pa_options INTERFACE
      -fsanitize=${PA_SANITIZE} -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    target_link_options(pa_options INTERFACE -fsanitize=${PA_SANITIZE})
  endif()
endif()

# libFuzzer 빌드(Linux clang 전용). core 와 시험은 coverage 계측만 받고, fuzz 실행 파일만 libFuzzer main 을 링크한다.
option(PA_FUZZ "libFuzzer 대상 빌드" OFF)
if(PA_FUZZ)
  if(MSVC OR NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "PA_FUZZ 는 Linux clang 에서만 지원한다.")
  endif()
  target_compile_options(pa_options INTERFACE -fsanitize=fuzzer-no-link)
  target_link_options(pa_options INTERFACE -fsanitize=fuzzer-no-link)
endif()

# Rust Vault 빌드·시험을 함께 돌릴지. C++ core 만 보는 fuzz preset 에서 끈다.
option(PA_WITH_VAULT "Rust Vault 를 cargo 로 빌드하고 시험" ON)
