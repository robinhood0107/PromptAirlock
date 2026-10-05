# core 소스 purity 검사(ADR 0001: core 는 I/O 를 하지 않는다).
add_test(NAME core_purity_check
  COMMAND ${CMAKE_COMMAND}
    "-DPA_PURITY_ROOTS=${PROJECT_SOURCE_DIR}/include/prompt_airlock/core;${PROJECT_SOURCE_DIR}/src/core"
    -P "${PROJECT_SOURCE_DIR}/cmake/CheckCorePurity.cmake")

# 검사기가 위반을 실제로 잡는지 확인한다. 위반 파일을 넣으면 실패해야 한다.
add_test(NAME core_purity_check_detects_violation
  COMMAND ${CMAKE_COMMAND}
    "-DPA_PURITY_ROOTS=${CMAKE_CURRENT_SOURCE_DIR}/violation"
    -P "${PROJECT_SOURCE_DIR}/cmake/CheckCorePurity.cmake")
set_tests_properties(core_purity_check_detects_violation PROPERTIES
  PASS_REGULAR_EXPRESSION "include-fstream.*include-chrono.*clock")
