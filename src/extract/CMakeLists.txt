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

