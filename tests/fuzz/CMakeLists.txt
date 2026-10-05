# libFuzzer 대상. ctest 가 대상마다 PA_FUZZ_SECONDS 동안 돌린다.
# seed corpus 는 빌드 디렉터리로 복사해 쓴다(libFuzzer 가 새 입력을 써 넣어도 소스 트리가 바뀌지 않게).
set(PA_FUZZ_SECONDS 60 CACHE STRING "fuzz 대상 하나를 ctest 에서 돌리는 시간(초)")

function(pa_add_fuzzer name)
  add_executable(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE prompt_airlock_core pa_options)
  target_link_options(${name} PRIVATE -fsanitize=fuzzer)

  set(corpus "${CMAKE_CURRENT_BINARY_DIR}/corpus/${name}")
  set(artifacts "${CMAKE_CURRENT_BINARY_DIR}/artifacts")
  file(MAKE_DIRECTORY "${corpus}" "${artifacts}")
  file(GLOB seeds "${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name}/*")
  file(COPY ${seeds} DESTINATION "${corpus}")

  add_test(NAME ${name}
    COMMAND ${name} -max_total_time=${PA_FUZZ_SECONDS} -timeout=5 -rss_limit_mb=2048 -seed=20261005
            -artifact_prefix=${artifacts}/${name}- "${corpus}")
  math(EXPR limit "${PA_FUZZ_SECONDS} + 60")
  set_tests_properties(${name} PROPERTIES TIMEOUT ${limit} LABELS fuzz)
endfunction()

pa_add_fuzzer(fuzz_utf8)
pa_add_fuzzer(fuzz_merge)
