find_package(boost_beast CONFIG REQUIRED)

# provider HTTPS 클라이언트. 자격 증명은 이 라이브러리만 다룬다.
add_library(prompt_airlock_provider https_client.cpp)
target_include_directories(prompt_airlock_provider PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(prompt_airlock_provider
  PUBLIC prompt_airlock_gateway
  PRIVATE Boost::beast pa_options)
if(MSVC)
  target_compile_options(prompt_airlock_provider PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_provider PRIVATE -Werror)
endif()
if(WIN32)
  target_link_libraries(prompt_airlock_provider PRIVATE crypt32)  # DPAPI
endif()
