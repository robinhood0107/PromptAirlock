cmake_minimum_required(VERSION 3.28)
project(prompt_airlock VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(PromptAirlockOptions)
include(RuntimeDlls)

enable_testing()
include(GoogleTest)
find_package(GTest CONFIG REQUIRED)

add_subdirectory(src/core)
add_subdirectory(tests/unit)
add_subdirectory(tests/purity)

include(Vault)
