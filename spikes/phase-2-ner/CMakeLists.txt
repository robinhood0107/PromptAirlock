cmake_minimum_required(VERSION 3.28)
project(prompt_airlock_phase2_ner_spike LANGUAGES CXX)

# Phase 2 NER / tokenizer / offset spike 전용이다. 최종 저장소 구조가 아니다.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(PA_SANITIZE "" CACHE STRING "sanitizer 목록: address")
set(PA_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH "저장소 루트")
set(PA_MODEL_DIR "${PA_REPO_ROOT}/models/phase-2" CACHE PATH "후보 모델 디렉터리(추적 안 함)")
set(PA_ORT_ROOT "${PA_REPO_ROOT}/_deps/onnxruntime-win-x64-1.30.0" CACHE PATH "ONNX Runtime 배포본 경로")

enable_testing()
include(GoogleTest)

find_package(GTest CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(utf8proc CONFIG REQUIRED)

add_library(pa_options INTERFACE)
if(MSVC)
  target_compile_options(pa_options INTERFACE /W4 /permissive- /EHsc /utf-8)
  target_compile_definitions(pa_options INTERFACE _WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  target_compile_options(pa_options INTERFACE -Wall -Wextra -Wpedantic)
endif()

if(PA_SANITIZE)
  if(NOT MSVC OR NOT PA_SANITIZE STREQUAL "address")
    message(FATAL_ERROR "이 spike 는 Windows clang-cl ASan 만 지원한다.")
  endif()
  # Phase 1 과 같은 방식: lld-link 직접 호출이므로 ASan 런타임을 명시 링크한다.
  target_compile_options(pa_options INTERFACE -fsanitize=address /Zi)
  execute_process(COMMAND "${CMAKE_CXX_COMPILER}" /clang:-print-resource-dir
                  OUTPUT_VARIABLE PA_CLANG_RESOURCE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(PA_CLANG_RT_DIR "${PA_CLANG_RESOURCE_DIR}/lib/windows")
  target_link_options(pa_options INTERFACE
    "/LIBPATH:${PA_CLANG_RT_DIR}" /INCREMENTAL:NO
    clang_rt.asan_dynamic-x86_64.lib
    /wholearchive:clang_rt.asan_dynamic_runtime_thunk-x86_64.lib)
  set(PA_ASAN_DLL "${PA_CLANG_RT_DIR}/clang_rt.asan_dynamic-x86_64.dll")
endif()

if(NOT EXISTS "${PA_ORT_ROOT}/include/onnxruntime_cxx_api.h")
  message(FATAL_ERROR "ONNX Runtime 배포본이 없다: ${PA_ORT_ROOT}")
endif()
add_library(pa_onnxruntime SHARED IMPORTED GLOBAL)
set_target_properties(pa_onnxruntime PROPERTIES
  IMPORTED_LOCATION "${PA_ORT_ROOT}/lib/onnxruntime.dll"
  IMPORTED_IMPLIB "${PA_ORT_ROOT}/lib/onnxruntime.lib"
  INTERFACE_INCLUDE_DIRECTORIES "${PA_ORT_ROOT}/include")

# 실행 파일 옆에 런타임 DLL 을 둔다. 전역 PATH 에 기대지 않는다.
function(pa_copy_runtime_dlls target)
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E $<IF:$<BOOL:$<TARGET_RUNTIME_DLLS:${target}>>,copy_if_different,true>
            $<TARGET_RUNTIME_DLLS:${target}> $<TARGET_FILE_DIR:${target}>
    COMMAND_EXPAND_LISTS)
  if(PA_ASAN_DLL)
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${PA_ASAN_DLL}" $<TARGET_FILE_DIR:${target}>)
  endif()
endfunction()

add_library(pa_ner STATIC
  src/text.cpp
  src/tokenizer.cpp
  src/model.cpp
  src/decode.cpp
  src/fixtures.cpp
  src/candidates.cpp
  src/pipeline.cpp
  src/eval.cpp)
target_include_directories(pa_ner PUBLIC src)
target_link_libraries(pa_ner PUBLIC pa_options pa_onnxruntime nlohmann_json::nlohmann_json utf8proc::utf8proc)

set(PA_FIXTURE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

add_executable(ner_bench tools/ner_bench.cpp)
target_link_libraries(ner_bench PRIVATE pa_ner psapi)
pa_copy_runtime_dlls(ner_bench)

add_executable(tok_dump tools/tok_dump.cpp)
target_link_libraries(tok_dump PRIVATE pa_ner)
pa_copy_runtime_dlls(tok_dump)

add_executable(ner_tests
  tests/text_test.cpp
  tests/tokenizer_test.cpp
  tests/decode_test.cpp
  tests/pipeline_test.cpp)
target_link_libraries(ner_tests PRIVATE pa_ner GTest::gtest GTest::gtest_main)
target_compile_definitions(ner_tests PRIVATE
  PA_MODEL_DIR="${PA_MODEL_DIR}" PA_FIXTURE_DIR="${PA_FIXTURE_DIR}")
pa_copy_runtime_dlls(ner_tests)
gtest_discover_tests(ner_tests DISCOVERY_MODE PRE_TEST)
