# 시험 전용 도구(결정적 난수 등). 운영 타깃은 링크하지 않는다.
add_library(pa_test_support INTERFACE)
target_include_directories(pa_test_support INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
