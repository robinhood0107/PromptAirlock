add_library(prompt_airlock_core version.cpp)
target_include_directories(prompt_airlock_core PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_compile_definitions(prompt_airlock_core PRIVATE PA_PROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(prompt_airlock_core PRIVATE pa_options)
