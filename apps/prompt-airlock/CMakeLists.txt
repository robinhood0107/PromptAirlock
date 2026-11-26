# 게이트웨이 실행 파일. Vault 를 함께 빌드할 때만 만든다.
set(PA_VAULT_EXE "${CMAKE_BINARY_DIR}/cargo/release/prompt-airlock-vault${CMAKE_EXECUTABLE_SUFFIX}")
add_executable(prompt-airlock main.cpp)
target_link_libraries(prompt-airlock PRIVATE prompt_airlock_audit prompt_airlock_gateway prompt_airlock_provider prompt_airlock_tls
                      prompt_airlock_vault_client prompt_airlock_ner pa_options)
# 문장 판별기 모델(ADR 0023)은 저장소 밖에서 학습해 내보낸 파일을 이 폴더에 둔다(classifier.json 해시로 고정).
set(PA_SENTENCE_MODEL_DIR "${CMAKE_BINARY_DIR}/models/sentence" CACHE PATH "문장 판별기 모델 폴더")
target_compile_definitions(prompt-airlock PRIVATE "PA_VAULT_EXE=\"${PA_VAULT_EXE}\"" PA_NER_MODEL_DIR="${PA_NER_MODEL_DIR}"
                           PA_SENTENCE_MODEL_DIR="${PA_SENTENCE_MODEL_DIR}")
add_dependencies(prompt-airlock prompt_airlock_vault prompt-airlock-extract)
pa_copy_runtime_dlls(prompt-airlock)
add_test(NAME prompt_airlock_check_cli_contract
  COMMAND ${CMAKE_COMMAND}
    "-DPA_APP=$<TARGET_FILE:prompt-airlock>"
    "-DPA_TEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/check-cli-contract"
    -P "${PROJECT_SOURCE_DIR}/tests/cmake/check_cli_command.cmake")
if(MSVC)
  target_compile_options(prompt-airlock PRIVATE /WX)
else()
  target_compile_options(prompt-airlock PRIVATE -Werror)
endif()
