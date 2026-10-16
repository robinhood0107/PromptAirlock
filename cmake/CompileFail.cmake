# "이렇게 쓰면 빌드되지 않는다"를 시험으로 고정한다.
# 사례 파일 하나에 #if PA_CF_OK / #else 로 정상 코드와 잘못된 코드를 한 줄만 다르게 둔다.
# - cf_<name>_ok  : PA_CF_OK=1 로 ALL 에 들어간다. 정상 짝이 빌드되지 않으면 전체 빌드가 실패한다.
# - cf_<name>_bad : EXCLUDE_FROM_ALL. ctest 가 이 타깃을 빌드하고, 기대한 진단(regex)이 나와야 통과한다.
#   regex 에는 그 사례의 식별자를 넣어 다른 이유(include 누락 등)의 실패로는 통과하지 않게 한다.
function(pa_add_compile_fail name source regex)
  set(libs ${ARGN})
  if(NOT libs)
    set(libs prompt_airlock_core)
  endif()

  add_library(cf_${name}_ok OBJECT "${source}")
  target_compile_definitions(cf_${name}_ok PRIVATE PA_CF_OK=1)
  target_link_libraries(cf_${name}_ok PRIVATE pa_options ${libs})

  add_library(cf_${name}_bad OBJECT EXCLUDE_FROM_ALL "${source}")
  target_compile_definitions(cf_${name}_bad PRIVATE PA_CF_OK=0)
  target_link_libraries(cf_${name}_bad PRIVATE pa_options ${libs})

  add_test(NAME compile_fail_${name}
    COMMAND "${CMAKE_COMMAND}" --build "${CMAKE_BINARY_DIR}" --target cf_${name}_bad)
  # 같은 빌드 디렉터리에서 ninja 를 동시에 돌리지 않도록 직렬로 실행한다.
  set_tests_properties(compile_fail_${name} PROPERTIES
    PASS_REGULAR_EXPRESSION "${regex}"
    RESOURCE_LOCK compile_fail
    TIMEOUT 180
    LABELS compile_fail)
endfunction()
