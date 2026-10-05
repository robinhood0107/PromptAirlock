pa_add_gtest(core_version_test core_version_test.cpp)
target_link_libraries(core_version_test PRIVATE prompt_airlock_core)
target_compile_definitions(core_version_test PRIVATE
  PA_PROJECT_VERSION="${PROJECT_VERSION}"
  PA_VAULT_PROTO="${PROJECT_SOURCE_DIR}/proto/vault_v1.proto")

# core 단위 시험: 파일 하나에 실행 파일 하나.
foreach(name IN ITEMS
    core_offset_test
    core_reason_test
    core_sensitive_test
    core_types_test
    core_utf8_test)
  pa_add_gtest(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE prompt_airlock_core)
endforeach()
