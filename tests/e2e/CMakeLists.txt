# 실제 Vault 프로세스로 하는 시험. PA_WITH_VAULT=ON(Vault 를 cargo 로 빌드)일 때만 만든다.
set(PA_VAULT_EXE "${CMAKE_BINARY_DIR}/cargo/release/prompt-airlock-vault${CMAKE_EXECUTABLE_SUFFIX}")

pa_add_gtest(vault_client_test vault_client_test.cpp)
target_link_libraries(vault_client_test PRIVATE prompt_airlock_vault_client)
target_compile_definitions(vault_client_test PRIVATE "PA_VAULT_EXE=\"${PA_VAULT_EXE}\"")
add_dependencies(vault_client_test prompt_airlock_vault)
