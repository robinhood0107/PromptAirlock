find_package(Protobuf CONFIG REQUIRED)
find_package(boost_asio CONFIG REQUIRED)

# proto/vault_v1.proto 에서 C++ 코드를 만든다. 생성 코드에는 프로젝트 경고를 오류로 다루지 않는다.
add_library(prompt_airlock_vault_proto STATIC "${PROJECT_SOURCE_DIR}/proto/vault_v1.proto")
target_link_libraries(prompt_airlock_vault_proto PUBLIC protobuf::libprotobuf PRIVATE pa_options)
set(PA_VAULT_PROTO_OUT "${CMAKE_CURRENT_BINARY_DIR}/gen")
file(MAKE_DIRECTORY "${PA_VAULT_PROTO_OUT}")
protobuf_generate(TARGET prompt_airlock_vault_proto LANGUAGE cpp
  IMPORT_DIRS "${PROJECT_SOURCE_DIR}/proto"
  PROTOC_OUT_DIR "${PA_VAULT_PROTO_OUT}")
target_include_directories(prompt_airlock_vault_proto PUBLIC "${PA_VAULT_PROTO_OUT}")
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # protobuf 생성 코드의 offsetof 사용(라이브러리 설계상 의도된 것)
  target_compile_options(prompt_airlock_vault_proto PRIVATE -Wno-invalid-offsetof)
endif()
if(MSVC AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # vcpkg protobuf DLL 은 MSVC 로 빌드되어 PROTOBUF_RESTRICT 가 비어 있다. clang-cl 에서는 __restrict 로 정의돼
  # 같은 함수의 이름 장식(mangling)이 달라 링크가 실패한다. protobuf 헤더를 쓰는 대상에서만 __restrict 를 비워 맞춘다.
  # 최적화 힌트만 빠지고 동작은 같다. protobuf 를 clang-cl 로 빌드하게 되면 지운다.
  target_compile_definitions(prompt_airlock_vault_proto PUBLIC __restrict=)
  target_compile_options(prompt_airlock_vault_proto PUBLIC -Wno-keyword-macro)
endif()

# Vault 프로세스 관리와 IPC 클라이언트(ADR 0001, 0003, 0019). core 에만 의존한다.
add_library(prompt_airlock_vault_client
  types.cpp)
target_include_directories(prompt_airlock_vault_client PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(prompt_airlock_vault_client
  PUBLIC prompt_airlock_core
  PRIVATE prompt_airlock_vault_proto Boost::asio pa_options)
if(MSVC)
  target_compile_options(prompt_airlock_vault_client PRIVATE /WX)
else()
  target_compile_options(prompt_airlock_vault_client PRIVATE -Werror)
  find_package(Threads REQUIRED)
  target_link_libraries(prompt_airlock_vault_client PUBLIC Threads::Threads)
endif()
