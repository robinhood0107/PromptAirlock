# 측정 도구. ALL 과 ctest 에 넣지 않고 필요할 때 빌드해 직접 실행한다(Phase 5 측정, 결정 #61 기준).
add_executable(detect_measure EXCLUDE_FROM_ALL detect_measure.cpp)
target_link_libraries(detect_measure PRIVATE prompt_airlock_detect pa_test_support pa_options)
pa_copy_runtime_dlls(detect_measure)
