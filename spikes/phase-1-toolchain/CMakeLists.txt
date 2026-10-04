cmake_minimum_required(VERSION 3.28)
project(prompt_airlock_phase1_spike LANGUAGES CXX)

# Phase 1 toolchain spike 전용이다. 최종 저장소 구조가 아니다.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(PA_SANITIZE "" CACHE STRING "sanitizer 목록: address / address,undefined / thread")
option(PA_WITH_DROGON "Drogon HTTPS 비교 spike 빌드" OFF)
set(PA_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH "저장소 루트")
set(PA_MODEL_DIR "${PA_REPO_ROOT}/models/phase-1" CACHE PATH "시험용 ONNX 모델 디렉터리")

enable_testing()
include(GoogleTest)

find_package(GTest CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)
find_package(boost_beast CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(pa_options INTERFACE)
if(MSVC)
  target_compile_options(pa_options INTERFACE /W4 /permissive- /EHsc /utf-8)
  target_compile_definitions(pa_options INTERFACE _WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  target_compile_options(pa_options INTERFACE -Wall -Wextra -Wpedantic)
endif()

if(PA_SANITIZE)
  if(MSVC)
    # clang-cl ASan 은 release CRT(/MD) 와만 동작한다.
    # CMake 은 lld-link 를 직접 부르므로 -fsanitize 링크 옵션이 런타임을 끌어오지 않는다. 런타임 라이브러리를 명시한다.
    if(NOT PA_SANITIZE STREQUAL "address")
      message(FATAL_ERROR "Windows 에서는 PA_SANITIZE=address 만 지원한다(UBSan 은 /MT 전용).")
    endif()
    target_compile_options(pa_options INTERFACE -fsanitize=address /Zi)
    execute_process(COMMAND "${CMAKE_CXX_COMPILER}" /clang:-print-resource-dir
                    OUTPUT_VARIABLE PA_CLANG_RESOURCE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(PA_CLANG_RT_DIR "${PA_CLANG_RESOURCE_DIR}/lib/windows")
    target_link_options(pa_options INTERFACE
      "/LIBPATH:${PA_CLANG_RT_DIR}" /INCREMENTAL:NO
      clang_rt.asan_dynamic-x86_64.lib
      /wholearchive:clang_rt.asan_dynamic_runtime_thunk-x86_64.lib)
    set(PA_ASAN_DLL "${PA_CLANG_RT_DIR}/clang_rt.asan_dynamic-x86_64.dll")
  else()
    target_compile_options(pa_options INTERFACE -fsanitize=${PA_SANITIZE} -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    target_link_options(pa_options INTERFACE -fsanitize=${PA_SANITIZE})
  endif()
endif()

# 테스트 실행 파일에 필요한 런타임 DLL 을 실행 파일 옆에 둔다. 전역 PATH 에 기대지 않는다.
function(pa_copy_runtime_dlls target)
  if(WIN32)
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E $<IF:$<BOOL:$<TARGET_RUNTIME_DLLS:${target}>>,copy_if_different,true>
              $<TARGET_RUNTIME_DLLS:${target}> $<TARGET_FILE_DIR:${target}>
      COMMAND_EXPAND_LISTS)
    if(PA_ASAN_DLL)
      add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${PA_ASAN_DLL}" $<TARGET_FILE_DIR:${target}>)
    endif()
  endif()
endfunction()

function(pa_add_gtest name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE pa_options GTest::gtest GTest::gtest_main)
  pa_copy_runtime_dlls(${name})
  gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST)
endfunction()

add_subdirectory(lang)
add_subdirectory(async)
add_subdirectory(net)
if(WIN32)
  endif()
