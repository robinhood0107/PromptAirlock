# ONNX Runtime 공식 배포본(바이너리)을 IMPORTED target 으로 쓴다. 소스 빌드하지 않는다.
set(PA_ORT_ROOT "${PA_REPO_ROOT}/_deps/onnxruntime-win-x64-1.30.0" CACHE PATH "ONNX Runtime 배포본 경로")
if(NOT EXISTS "${PA_ORT_ROOT}/include/onnxruntime_cxx_api.h")
  message(FATAL_ERROR "ONNX Runtime 배포본이 없다: ${PA_ORT_ROOT}")
endif()

add_library(pa_onnxruntime SHARED IMPORTED GLOBAL)
set_target_properties(pa_onnxruntime PROPERTIES
  IMPORTED_LOCATION "${PA_ORT_ROOT}/lib/onnxruntime.dll"
  IMPORTED_IMPLIB "${PA_ORT_ROOT}/lib/onnxruntime.lib"
  INTERFACE_INCLUDE_DIRECTORIES "${PA_ORT_ROOT}/include")

pa_add_gtest(ort_minimal_test ort_minimal_test.cpp)
target_link_libraries(ort_minimal_test PRIVATE pa_onnxruntime)
target_compile_definitions(ort_minimal_test PRIVATE PA_MODEL_DIR="${PA_MODEL_DIR}")

# 실행 파일 옆 DLL 배치 결과를 확인한다(onnxruntime.dll 존재, providers_shared 는 CPU 경로에 불필요).
add_test(NAME ort_runtime_dll_beside_exe
  COMMAND ${CMAKE_COMMAND} -E cat "$<TARGET_FILE_DIR:ort_minimal_test>/onnxruntime.dll")
set_tests_properties(ort_runtime_dll_beside_exe PROPERTIES PASS_REGULAR_EXPRESSION "MZ")
