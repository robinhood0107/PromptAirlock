add_library(prompt_airlock_core
  document.cpp
  encoded.cpp
  entity.cpp
  grade.cpp
  link_context.cpp
  merge.cpp
  policy.cpp
  privacy.cpp
  prompt.cpp
  provider_boundary.cpp
  reason.cpp
  request_params.cpp
  residual.cpp
  sensitive.cpp
  token.cpp
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

# 연구·시험 전용 라이브러리. 연구용 열쇠(make_research_only)의 정의는 여기에만 있다.
# 운영 실행 파일(Phase 8 apps/)은 이 타깃을 링크하지 않는다.
add_library(prompt_airlock_core_research research/research_only.cpp)
target_compile_definitions(prompt_airlock_core_research PUBLIC PA_CORE_RESEARCH=1)
target_link_libraries(prompt_airlock_core_research PUBLIC prompt_airlock_core PRIVATE pa_options)
