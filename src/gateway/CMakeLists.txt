find_package(nlohmann_json CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)
find_package(boost_beast CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# HTTP 입구(ADR 0004, 0020): 설정, 출처 인증, 고정 오류 응답, HTTPS 서버(Beast + coroutine), 요청 처리 단계.
add_library(prompt_airlock_gateway
  auth.cpp
  config.cpp
  error_body.cpp
  pipeline.cpp
  provider_json.cpp
  request_json.cpp
  server.cpp)
target_include_directories(prompt_airlock_gateway PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(prompt_airlock_gateway
  PUBLIC prompt_airlock_core prompt_airlock_detect Boost::asio OpenSSL::SSL
  PRIVATE nlohmann_json::nlohmann_json Boost::beast pa_options)
if(MSVC)
  target_compile_options(prompt_airlock_gateway PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_gateway PRIVATE -Werror)
endif()
