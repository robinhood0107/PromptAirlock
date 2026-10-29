# 실행 파일이 쓰는 런타임 DLL 을 실행 파일 옆에 둔다. 전역 PATH 에 기대지 않는다(docs/adr/0009).
# 같은 폴더로 같은 DLL 을 여러 링크가 동시에 복사하면 Windows 에서 파일이 잠겨 "permission denied" 로 실패한다.
# DLL 이 아직 없는 깨끗한 빌드에서만 드러난다. DLL 을 복사하는 대상의 링크(빌드 직후 복사 포함)를 한 줄로 세운다.
# Ninja 전용 속성이며 다른 생성기는 무시한다.
set_property(GLOBAL APPEND PROPERTY JOB_POOLS pa_runtime_dll_copy=1)

function(pa_copy_runtime_dlls target)
  if(NOT WIN32)
    return()
  endif()
  set_property(TARGET ${target} PROPERTY JOB_POOL_LINK pa_runtime_dll_copy)
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E $<IF:$<BOOL:$<TARGET_RUNTIME_DLLS:${target}>>,copy_if_different,true>
            $<TARGET_RUNTIME_DLLS:${target}> $<TARGET_FILE_DIR:${target}>
    COMMAND_EXPAND_LISTS)
  if(PA_ASAN_DLL)
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${PA_ASAN_DLL}" $<TARGET_FILE_DIR:${target}>)
  endif()
endfunction()

function(pa_add_gtest name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE pa_options GTest::gtest GTest::gtest_main)
  pa_copy_runtime_dlls(${name})
  # 동시성 시험이 멈추면 ctest 가 끝없이 기다리지 않게 시험 하나에 300초 상한을 둔다(sanitizer 빌드 여유 포함).
  if(NOT WIN32 AND PA_SANITIZE MATCHES "address")
    # ONNX Runtime 내부의 한 번짜리 할당만 누수 보고에서 뺀다(tests/lsan.supp).
    gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST
      PROPERTIES TIMEOUT 300 ENVIRONMENT "LSAN_OPTIONS=suppressions=${PROJECT_SOURCE_DIR}/tests/lsan.supp")
  elseif(NOT WIN32 AND PA_SANITIZE STREQUAL "thread")
    # ONNX Runtime 종료 처리 중 경합만 뺀다(tests/tsan.supp).
    gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST
      PROPERTIES TIMEOUT 300 ENVIRONMENT "TSAN_OPTIONS=suppressions=${PROJECT_SOURCE_DIR}/tests/tsan.supp")
  else()
    gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST PROPERTIES TIMEOUT 300)
  endif()
endfunction()
