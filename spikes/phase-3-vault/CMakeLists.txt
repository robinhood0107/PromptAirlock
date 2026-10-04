cmake_minimum_required(VERSION 3.28)
project(prompt_airlock_phase3_vault LANGUAGES CXX)

# Phase 3 Vault/IPC spike 전용이다. 최종 저장소 구조가 아니다.
# 구성 단계에서 vcpkg 가 protobuf(protoc 포함)를 설치하고, 빌드 단계에서 그 protoc 로 Rust Vault 를 cargo 빌드한다.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(PA_SANITIZE "" CACHE STRING "sanitizer 목록: address / thread")
set(PA_CARGO_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/target" CACHE PATH "cargo 출력 디렉터리")
option(PA_WITH_FFI_LEARNING "학습용 Rust cdylib FFI 시험(Windows)" ON)

enable_testing()
include(GoogleTest)

find_package(GTest CONFIG REQUIRED)
find_package(Protobuf CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)
find_program(PA_CARGO cargo REQUIRED)

add_library(pa_options INTERFACE)
if(MSVC)
  target_compile_options(pa_options INTERFACE /W4 /permissive- /EHsc /utf-8)
  target_compile_definitions(pa_options INTERFACE _WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  target_compile_options(pa_options INTERFACE -Wall -Wextra -Wpedantic)
endif()

if(PA_SANITIZE)
  if(MSVC)
    # Phase 1 과 같은 방식: clang-cl ASan 은 /MD 와만 동작하고 런타임을 직접 링크한다.
    if(NOT PA_SANITIZE STREQUAL "address")
      message(FATAL_ERROR "Windows 에서는 PA_SANITIZE=address 만 지원한다.")
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
    target_compile_options(pa_options INTERFACE -fsanitize=${PA_SANITIZE} -fno-omit-frame-pointer)
    target_link_options(pa_options INTERFACE -fsanitize=${PA_SANITIZE})
  endif()
endif()

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

# Rust workspace(vault + ffi-learning). PROTOC 는 vcpkg 가 빌드한 protoc 를 넘긴다.
set(PA_VAULT_EXE "${PA_CARGO_TARGET_DIR}/release/prompt-airlock-vault${CMAKE_EXECUTABLE_SUFFIX}")
set(PA_CARGO_ENV ${CMAKE_COMMAND} -E env "PROTOC=$<TARGET_FILE:protobuf::protoc>" "CARGO_TARGET_DIR=${PA_CARGO_TARGET_DIR}")
set(PA_FFI_BYPRODUCTS "")
if(WIN32)
  set(PA_FFI_BYPRODUCTS "${PA_CARGO_TARGET_DIR}/release/pa_ffi_learning.dll" "${PA_CARGO_TARGET_DIR}/release/pa_ffi_learning.dll.lib")
endif()
add_custom_target(pa_rust_build ALL
  COMMAND ${PA_CARGO_ENV} "${PA_CARGO}" build --release --locked --workspace
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  BYPRODUCTS "${PA_VAULT_EXE}" ${PA_FFI_BYPRODUCTS}
  USES_TERMINAL
  COMMENT "cargo build --release (Rust Vault)")

add_test(NAME rust_cargo_test
  COMMAND ${PA_CARGO_ENV} "${PA_CARGO}" test --release --locked --workspace
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
set_tests_properties(rust_cargo_test PROPERTIES TIMEOUT 600)

add_subdirectory(cpp-client)
