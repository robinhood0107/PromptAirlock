# 실행 파일이 쓰는 런타임 DLL 을 실행 파일 옆에 둔다. 전역 PATH 에 기대지 않는다(docs/adr/0009).
function(pa_copy_runtime_dlls target)
  if(NOT WIN32)
    return()
  endif()
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
  gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST)
endfunction()
