find_package(nlohmann_json CONFIG REQUIRED)
find_package(utf8proc CONFIG REQUIRED)

# NER 모듈(ADR 0001, 0006): tokenizer 와 추론. core 와 detect 는 이 모듈을 모른다.
add_library(prompt_airlock_ner
  engine.cpp
  model_files.cpp
  session.cpp
  sha256.cpp
  tokenizer.cpp
  windows.cpp)
target_include_directories(prompt_airlock_ner PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(prompt_airlock_ner
  PUBLIC prompt_airlock_core prompt_airlock_detect
  PRIVATE pa_options nlohmann_json::nlohmann_json pa::onnxruntime utf8proc::utf8proc)
if(MSVC)
  target_compile_options(prompt_airlock_ner PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_ner PRIVATE -Werror)
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  target_compile_options(prompt_airlock_ner PRIVATE -Wglobal-constructors -Wexit-time-destructors)
endif()
