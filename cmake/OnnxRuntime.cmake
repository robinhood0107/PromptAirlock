# ONNX Runtime 공식 배포본을 받아 pa::onnxruntime(SHARED IMPORTED)로 노출한다(ADR 0005, 0009).
# 배포본은 _deps/ 에 풀고, 이미 있으면 다시 받지 않는다. 해시가 다르면 설정이 실패한다.
set(PA_ORT_VERSION 1.30.0)
set(PA_ORT_NUGET_SHA256 30df119bd9164eaa187666d93147448fdd4a9a1a3caf83f1505daf7af2d1c5d2)
if(WIN32)
  set(PA_ORT_RID win-x64)
  set(PA_ORT_NAME onnxruntime-win-x64-${PA_ORT_VERSION})
  set(PA_ORT_ARCHIVE ${PA_ORT_NAME}.zip)
  set(PA_ORT_SHA256 c6ba983baf5681af108599675d2a89c2d145512d02de28aed0bff177cd0ba949)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
  set(PA_ORT_RID linux-x64)
  set(PA_ORT_NAME onnxruntime-linux-x64-${PA_ORT_VERSION})
  set(PA_ORT_ARCHIVE ${PA_ORT_NAME}.tgz)
  set(PA_ORT_SHA256 a5ed5a3cac51fbb2e90da632ae43d19212faaa20e76484e62bcb7c23ddb3b3fd)
else()
  message(FATAL_ERROR "ONNX Runtime 배포본을 지원하지 않는 플랫폼이다: ${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(PA_ORT_ROOT "${PROJECT_SOURCE_DIR}/_deps/${PA_ORT_NAME}")
if(NOT EXISTS "${PA_ORT_ROOT}/include/onnxruntime_cxx_api.h"
   OR (NOT WIN32 AND NOT EXISTS "${PA_ORT_ROOT}/lib/libonnxruntime.so.${PA_ORT_VERSION}"))
  include(DownloadVerified)
  file(MAKE_DIRECTORY "${PROJECT_SOURCE_DIR}/_deps")
  set(archive "${PROJECT_SOURCE_DIR}/_deps/${PA_ORT_ARCHIVE}")
  message(STATUS "ONNX Runtime ${PA_ORT_VERSION} 를 받는다")
  pa_download_verified(
    "https://github.com/microsoft/onnxruntime/releases/download/v${PA_ORT_VERSION}/${PA_ORT_ARCHIVE}"
    "${archive}" "${PA_ORT_SHA256}" downloaded)
  if(downloaded)
    file(ARCHIVE_EXTRACT INPUT "${archive}" DESTINATION "${PROJECT_SOURCE_DIR}/_deps")
  else()
    message(STATUS "기본 배포처에 연결할 수 없어 공식 NuGet 패키지를 받는다")
    set(archive "${PROJECT_SOURCE_DIR}/_deps/microsoft.ml.onnxruntime.${PA_ORT_VERSION}.nupkg")
    pa_download_verified(
      "https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime/${PA_ORT_VERSION}/microsoft.ml.onnxruntime.${PA_ORT_VERSION}.nupkg"
      "${archive}" "${PA_ORT_NUGET_SHA256}" downloaded)
    if(NOT downloaded)
      message(FATAL_ERROR "ONNX Runtime 공식 배포처 2곳에서 모두 받지 못했다")
    endif()
    set(unpacked "${PROJECT_SOURCE_DIR}/_deps/onnxruntime-nuget-${PA_ORT_VERSION}")
    file(ARCHIVE_EXTRACT INPUT "${archive}" DESTINATION "${unpacked}")
    if(NOT WIN32)
      # 중단된 설치의 기존 별칭을 제거해 이름을 바꿀 때 순환 링크가 생기지 않게 한다.
      file(REMOVE "${PA_ORT_ROOT}/lib/libonnxruntime.so")
    endif()
    file(COPY "${unpacked}/runtimes/${PA_ORT_RID}/native/" DESTINATION "${PA_ORT_ROOT}/lib")
    if(NOT WIN32)
      file(RENAME "${PA_ORT_ROOT}/lib/libonnxruntime.so"
        "${PA_ORT_ROOT}/lib/libonnxruntime.so.${PA_ORT_VERSION}")
      file(CREATE_LINK "libonnxruntime.so.${PA_ORT_VERSION}" "${PA_ORT_ROOT}/lib/libonnxruntime.so.1" SYMBOLIC)
      file(CREATE_LINK "libonnxruntime.so.${PA_ORT_VERSION}" "${PA_ORT_ROOT}/lib/libonnxruntime.so" SYMBOLIC)
    endif()
    file(COPY "${unpacked}/LICENSE" "${unpacked}/ThirdPartyNotices.txt" DESTINATION "${PA_ORT_ROOT}")
    # 헤더는 마지막에 복사해 불완전한 설치를 다음 설정에서 재사용하지 않는다.
    file(COPY "${unpacked}/build/native/include/" DESTINATION "${PA_ORT_ROOT}/include")
    file(REMOVE_RECURSE "${unpacked}")
  endif()
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
