find_package(nlohmann_json CONFIG REQUIRED)

# 감사 기록(ADR 0021). 로컬 파일만 쓴다.
add_library(prompt_airlock_audit log.cpp)
target_include_directories(prompt_airlock_audit PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(prompt_airlock_audit PUBLIC prompt_airlock_core nlohmann_json::nlohmann_json PRIVATE pa_options)
if(MSVC)
  target_compile_options(prompt_airlock_audit PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_audit PRIVATE -Werror)
endif()
