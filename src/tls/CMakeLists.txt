find_package(OpenSSL REQUIRED)
find_package(boost_asio CONFIG REQUIRED)

# TLS 설정(ADR 0014). OpenSSL 을 직접 부르는 곳은 이 모듈뿐이다.
add_library(prompt_airlock_tls context.cpp)
target_include_directories(prompt_airlock_tls PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(prompt_airlock_tls PUBLIC Boost::asio OpenSSL::SSL OpenSSL::Crypto PRIVATE pa_options)
if(MSVC)
  target_compile_options(prompt_airlock_tls PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_tls PRIVATE -Werror)
endif()
