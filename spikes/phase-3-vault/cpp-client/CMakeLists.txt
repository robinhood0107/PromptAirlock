# proto 에서 C++ 코드를 만든다. 생성 코드에는 프로젝트 경고 옵션을 적용하지 않는다.
add_library(pa_vault_proto STATIC "${CMAKE_CURRENT_SOURCE_DIR}/../proto/vault_v1.proto")
# sanitizer 옵션(ASan 의 STL annotation 등)은 모든 C++ 목적 파일이 같아야 링크된다.
target_link_libraries(pa_vault_proto PUBLIC protobuf::libprotobuf PRIVATE pa_options)
set(PA_PROTO_OUT "${CMAKE_CURRENT_BINARY_DIR}/gen")
file(MAKE_DIRECTORY "${PA_PROTO_OUT}")
protobuf_generate(TARGET pa_vault_proto LANGUAGE cpp
  IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/../proto"
  PROTOC_OUT_DIR "${PA_PROTO_OUT}")
target_include_directories(pa_vault_proto PUBLIC "${PA_PROTO_OUT}")
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # protobuf 생성 코드의 offsetof 경고(라이브러리 설계상 의도된 사용)
  target_compile_options(pa_vault_proto PRIVATE -Wno-invalid-offsetof)
endif()

add_library(pa_vault_client STATIC src/types.cpp src/stream.cpp src/client.cpp src/process.cpp)
target_include_directories(pa_vault_client PUBLIC include)
target_link_libraries(pa_vault_client PUBLIC pa_vault_proto Boost::asio PRIVATE pa_options)
if(NOT WIN32)
  target_compile_options(pa_vault_client PUBLIC -pthread)
  target_link_options(pa_vault_client PUBLIC -pthread)
endif()

add_executable(pa_vault_e2e_test test/e2e_test.cpp)
target_link_libraries(pa_vault_e2e_test PRIVATE pa_options pa_vault_client GTest::gtest GTest::gtest_main)
target_compile_definitions(pa_vault_e2e_test PRIVATE "PA_VAULT_EXE=\"${PA_VAULT_EXE}\"")
add_dependencies(pa_vault_e2e_test pa_rust_build)
pa_copy_runtime_dlls(pa_vault_e2e_test)
gtest_discover_tests(pa_vault_e2e_test DISCOVERY_MODE PRE_TEST PROPERTIES TIMEOUT 120)

add_executable(pa_vault_bench bench/vault_bench.cpp)
target_link_libraries(pa_vault_bench PRIVATE pa_options pa_vault_client)
add_dependencies(pa_vault_bench pa_rust_build)
pa_copy_runtime_dlls(pa_vault_bench)

if(WIN32 AND PA_WITH_FFI_LEARNING)
  # 학습용 cdylib. 운영 구조가 아니다.
  add_library(pa_ffi_learning SHARED IMPORTED)
  set_target_properties(pa_ffi_learning PROPERTIES
    IMPORTED_LOCATION "${PA_CARGO_TARGET_DIR}/release/pa_ffi_learning.dll"
    IMPORTED_IMPLIB "${PA_CARGO_TARGET_DIR}/release/pa_ffi_learning.dll.lib")
  add_executable(pa_ffi_learning_test test/ffi_learning_test.cpp)
  target_link_libraries(pa_ffi_learning_test PRIVATE pa_options pa_ffi_learning GTest::gtest GTest::gtest_main)
  add_dependencies(pa_ffi_learning_test pa_rust_build)
  pa_copy_runtime_dlls(pa_ffi_learning_test)
  gtest_discover_tests(pa_ffi_learning_test DISCOVERY_MODE PRE_TEST)
endif()
