add_library(prompt_airlock_core
  sensitive.cpp
  utf8.cpp
  version.cpp)
target_include_directories(prompt_airlock_core PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_compile_definitions(prompt_airlock_core PRIVATE PA_PROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(prompt_airlock_core PRIVATE pa_options)
# core 는 외부 의존이 없으므로 경고를 오류로 다룬다. clang 은 생성자가 있는 전역도 막는다.
if(MSVC)
  target_compile_options(prompt_airlock_core PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_core PRIVATE -Werror)
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  target_compile_options(prompt_airlock_core PRIVATE -Wglobal-constructors -Wexit-time-destructors)
endif()
