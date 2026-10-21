find_package(nlohmann_json CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)

# HTTP 입구(ADR 0020): 설정.
add_library(prompt_airlock_gateway
  config.cpp)
target_include_directories(prompt_airlock_gateway PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(prompt_airlock_gateway
  PUBLIC prompt_airlock_core
  PRIVATE nlohmann_json::nlohmann_json Boost::asio pa_options)
if(MSVC)
  target_compile_options(prompt_airlock_gateway PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_gateway PRIVATE -Werror)
endif()
