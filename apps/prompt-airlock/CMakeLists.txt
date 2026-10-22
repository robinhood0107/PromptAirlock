# 게이트웨이 실행 파일. Vault 를 함께 빌드할 때만 만든다.
set(PA_VAULT_EXE "${CMAKE_BINARY_DIR}/cargo/release/prompt-airlock-vault${CMAKE_EXECUTABLE_SUFFIX}")
add_executable(prompt-airlock main.cpp)
target_link_libraries(prompt-airlock PRIVATE prompt_airlock_audit prompt_airlock_gateway prompt_airlock_provider prompt_airlock_tls
                      prompt_airlock_vault_client prompt_airlock_ner pa_options)
target_compile_definitions(prompt-airlock PRIVATE "PA_VAULT_EXE=\"${PA_VAULT_EXE}\"" PA_NER_MODEL_DIR="${PA_NER_MODEL_DIR}")
add_dependencies(prompt-airlock prompt_airlock_vault)
pa_copy_runtime_dlls(prompt-airlock)
if(MSVC)
  target_compile_options(prompt-airlock PRIVATE /WX)
else()
  target_compile_options(prompt-airlock PRIVATE -Werror)
endif()
