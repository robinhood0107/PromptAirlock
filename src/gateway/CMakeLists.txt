find_package(nlohmann_json CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)
find_package(boost_beast CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/console/confirm.html" PA_CONFIRM_HTML)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/console/confirm.js" PA_CONFIRM_JS)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/console/confirm.css" PA_CONFIRM_CSS)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/console/confirm.svg" PA_CONFIRM_SVG)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/console/confirm.html"
  "${CMAKE_CURRENT_SOURCE_DIR}/console/confirm.js"
  "${CMAKE_CURRENT_SOURCE_DIR}/console/confirm.css"
  "${CMAKE_CURRENT_SOURCE_DIR}/console/confirm.svg")
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(console_assets.hpp.in "generated/console_assets.hpp" @ONLY)

# HTTP 입구(ADR 0004, 0020): 설정, 출처 인증, 고정 오류 응답, HTTPS 서버(Beast + coroutine), 요청 처리 단계.
add_library(prompt_airlock_gateway
  auth.cpp
  config.cpp
  confirm.cpp
  documents.cpp
  error_body.cpp
  pipeline.cpp
  provider_json.cpp
  "${PROJECT_SOURCE_DIR}/src/provider/cli_client.cpp"
  response_json.cpp
  request_json.cpp
  server.cpp)
target_include_directories(prompt_airlock_gateway PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_include_directories(prompt_airlock_gateway PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(prompt_airlock_gateway
  PUBLIC prompt_airlock_core prompt_airlock_detect prompt_airlock_audit Boost::asio OpenSSL::SSL
  PRIVATE prompt_airlock_extract_client nlohmann_json::nlohmann_json Boost::beast pa_options)
if(MSVC)
  target_compile_options(prompt_airlock_gateway PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_gateway PRIVATE -Werror)
endif()
