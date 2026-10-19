# 측정 도구. ALL 과 ctest 에 넣지 않고 필요할 때 빌드해 직접 실행한다(Phase 5 측정, 결정 #61 기준).
add_executable(detect_measure EXCLUDE_FROM_ALL detect_measure.cpp)
target_link_libraries(detect_measure PRIVATE prompt_airlock_detect pa_test_support pa_options)
pa_copy_runtime_dlls(detect_measure)

# Vault 발급·복원 지연(Phase 6 측정). 실제 Vault 실행 파일이 필요하다.
if(PA_WITH_VAULT)
  add_executable(vault_measure EXCLUDE_FROM_ALL vault_measure.cpp)
  target_link_libraries(vault_measure PRIVATE prompt_airlock_vault_client prompt_airlock_detect pa_test_support pa_options)
  target_compile_definitions(vault_measure PRIVATE
    "PA_VAULT_EXE=\"${CMAKE_BINARY_DIR}/cargo/release/prompt-airlock-vault${CMAKE_EXECUTABLE_SUFFIX}\"")
  add_dependencies(vault_measure prompt_airlock_vault)
  pa_copy_runtime_dlls(vault_measure)
endif()