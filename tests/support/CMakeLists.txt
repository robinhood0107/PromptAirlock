# 시험 전용 도구(결정적 난수 등). 운영 타깃은 링크하지 않는다.
add_library(pa_test_support INTERFACE)
target_include_directories(pa_test_support INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")

# 시험 전용 자체 서명 인증서(실행 때마다 새 키, 메모리에만). TLS·HTTP 시험이 링크한다.
find_package(OpenSSL REQUIRED)
add_library(pa_test_cert STATIC test_cert.cpp)
target_include_directories(pa_test_cert PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(pa_test_cert PUBLIC OpenSSL::SSL OpenSSL::Crypto PRIVATE pa_options)
