find_package(boost_beast CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# 시험·시연용 mock provider. 시험은 라이브러리를 직접 띄우고, 시연은 실행 파일을 쓴다.
add_library(pa_mock_provider STATIC mock_provider.cpp)
target_include_directories(pa_mock_provider PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(pa_mock_provider
  PUBLIC Boost::asio OpenSSL::SSL prompt_airlock_core
  PRIVATE Boost::beast nlohmann_json::nlohmann_json pa_options)

add_executable(mock-provider main.cpp)
target_link_libraries(mock-provider PRIVATE pa_mock_provider prompt_airlock_tls pa_options)
pa_copy_runtime_dlls(mock-provider)
