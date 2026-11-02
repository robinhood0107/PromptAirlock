find_package(libzip CONFIG REQUIRED)
find_package(expat CONFIG REQUIRED)

# 문서 추출(ADR 0028). 파일 byte 를 해석하므로 추출 실행 파일과 시험·fuzz 만 링크한다(게이트웨이는 링크하지 않음).
add_library(prompt_airlock_extract
  extract.cpp
  hwpx.cpp
  ooxml.cpp
  text.cpp
  xml.cpp
  zip.cpp)
target_include_directories(prompt_airlock_extract PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(prompt_airlock_extract PRIVATE libzip::zip expat::expat pa_options)
if(MSVC)
  target_compile_options(prompt_airlock_extract PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_extract PRIVATE -Werror)
endif()

# 게이트웨이 쪽: 추출 자식 실행기와 주고받는 JSON. 파일 해석 라이브러리(libzip, expat)는 링크하지 않는다.
find_package(nlohmann_json CONFIG REQUIRED)
add_library(prompt_airlock_extract_client protocol.cpp runner.cpp)
target_include_directories(prompt_airlock_extract_client PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(prompt_airlock_extract_client PRIVATE nlohmann_json::nlohmann_json pa_options)
if(MSVC)
  target_compile_options(prompt_airlock_extract_client PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_extract_client PRIVATE -Werror)
endif()

# 추출 실행 파일(ADR 0028). 게이트웨이가 요청마다 자식으로 띄운다.
add_executable(prompt-airlock-extract "${PROJECT_SOURCE_DIR}/apps/prompt-airlock-extract/main.cpp")
target_link_libraries(prompt-airlock-extract PRIVATE prompt_airlock_extract prompt_airlock_extract_client pa_options)
pa_copy_runtime_dlls(prompt-airlock-extract)
if(MSVC)
  target_compile_options(prompt-airlock-extract PRIVATE /WX)
else()
  target_compile_options(prompt-airlock-extract PRIVATE -Werror)
endif()
