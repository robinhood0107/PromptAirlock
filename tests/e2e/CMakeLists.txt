# 실제 Vault 프로세스로 하는 시험. PA_WITH_VAULT=ON(Vault 를 cargo 로 빌드)일 때만 만든다.
set(PA_VAULT_EXE "${CMAKE_BINARY_DIR}/cargo/release/prompt-airlock-vault${CMAKE_EXECUTABLE_SUFFIX}")

foreach(name IN ITEMS vault_client_test vault_pipeline_test)
  pa_add_gtest(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE prompt_airlock_vault_client)
  target_compile_definitions(${name} PRIVATE "PA_VAULT_EXE=\"${PA_VAULT_EXE}\"")
  add_dependencies(${name} prompt_airlock_vault)
endforeach()
find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(vault_pipeline_test PRIVATE prompt_airlock_detect prompt_airlock_ner pa_test_support
                      nlohmann_json::nlohmann_json)
target_compile_definitions(vault_pipeline_test PRIVATE PA_NER_MODEL_DIR="${PA_NER_MODEL_DIR}"
                           PA_NER_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/ner")
