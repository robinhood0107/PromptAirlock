pa_add_gtest(core_version_test core_version_test.cpp)
target_link_libraries(core_version_test PRIVATE prompt_airlock_core)
target_compile_definitions(core_version_test PRIVATE
  PA_PROJECT_VERSION="${PROJECT_VERSION}"
  PA_VAULT_PROTO="${PROJECT_SOURCE_DIR}/proto/vault_v1.proto")
