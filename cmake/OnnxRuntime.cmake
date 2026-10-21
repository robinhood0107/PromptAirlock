# ONNX Runtime 공식 배포본을 받아 pa::onnxruntime(SHARED IMPORTED)로 노출한다(ADR 0005, 0009).
# 배포본은 _deps/ 에 풀고, 이미 있으면 다시 받지 않는다. 해시가 다르면 설정이 실패한다.
set(PA_ORT_VERSION 1.30.0)
if(WIN32)
  set(PA_ORT_NAME onnxruntime-win-x64-${PA_ORT_VERSION})
  set(PA_ORT_ARCHIVE ${PA_ORT_NAME}.zip)
  set(PA_ORT_SHA256 c6ba983baf5681af108599675d2a89c2d145512d02de28aed0bff177cd0ba949)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
  set(PA_ORT_NAME onnxruntime-linux-x64-${PA_ORT_VERSION})
  set(PA_ORT_ARCHIVE ${PA_ORT_NAME}.tgz)
  set(PA_ORT_SHA256 a5ed5a3cac51fbb2e90da632ae43d19212faaa20e76484e62bcb7c23ddb3b3fd)
else()
  message(FATAL_ERROR "ONNX Runtime 배포본을 지원하지 않는 플랫폼이다: ${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(PA_ORT_ROOT "${PROJECT_SOURCE_DIR}/_deps/${PA_ORT_NAME}")
if(NOT EXISTS "${PA_ORT_ROOT}/include/onnxruntime_cxx_api.h")
  set(archive "${PROJECT_SOURCE_DIR}/_deps/${PA_ORT_ARCHIVE}")
  message(STATUS "ONNX Runtime ${PA_ORT_VERSION} 를 받는다")
  file(DOWNLOAD
    "https://github.com/microsoft/onnxruntime/releases/download/v${PA_ORT_VERSION}/${PA_ORT_ARCHIVE}"
    "${archive}" EXPECTED_HASH SHA256=${PA_ORT_SHA256} SHOW_PROGRESS)
  file(ARCHIVE_EXTRACT INPUT "${archive}" DESTINATION "${PROJECT_SOURCE_DIR}/_deps")
  file(REMOVE "${archive}")
endif()

add_library(pa::onnxruntime SHARED IMPORTED GLOBAL)
if(WIN32)
  set_target_properties(pa::onnxruntime PROPERTIES
    IMPORTED_LOCATION "${PA_ORT_ROOT}/lib/onnxruntime.dll"
    IMPORTED_IMPLIB "${PA_ORT_ROOT}/lib/onnxruntime.lib")
else()
  # 링크하는 타깃의 빌드 RPATH 에 이 디렉터리가 자동으로 들어간다.
  set_target_properties(pa::onnxruntime PROPERTIES
    IMPORTED_LOCATION "${PA_ORT_ROOT}/lib/libonnxruntime.so.${PA_ORT_VERSION}"
    IMPORTED_SONAME "libonnxruntime.so.1")
endif()
set_target_properties(pa::onnxruntime PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${PA_ORT_ROOT}/include")
