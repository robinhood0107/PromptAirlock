find_package(utf8proc CONFIG REQUIRED)

# 결정론 탐지기(ADR 0001, 0018). core 와 같은 금지 패턴을 지키고 경고를 오류로 다룬다.
add_library(prompt_airlock_detect
  accounts.cpp
  credentials.cpp
  detectors.cpp
  encoded.cpp
  identifiers.cpp
  network.cpp
  scan.cpp
  secrets.cpp
  sensitive.cpp
  terms.cpp
  view.cpp)
target_include_directories(prompt_airlock_detect PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(prompt_airlock_detect PUBLIC prompt_airlock_core PRIVATE pa_options utf8proc::utf8proc)
if(MSVC)
  target_compile_options(prompt_airlock_detect PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_detect PRIVATE -Werror)
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  target_compile_options(prompt_airlock_detect PRIVATE -Wglobal-constructors -Wexit-time-destructors)
endif()
