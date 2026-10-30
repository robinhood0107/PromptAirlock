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
# NER 정확도·지연·부하(Phase 7-3). 큰 합성 셋과 모델이 필요하다. Vault 가 있으면 잔여 검사도 잰다.
find_package(nlohmann_json CONFIG REQUIRED)
find_package(utf8proc CONFIG REQUIRED)
add_executable(ner_measure EXCLUDE_FROM_ALL ner_measure.cpp)
target_link_libraries(ner_measure PRIVATE prompt_airlock_ner prompt_airlock_detect pa_options
                      nlohmann_json::nlohmann_json utf8proc::utf8proc)
target_compile_definitions(ner_measure PRIVATE PA_NER_MODEL_DIR="${PA_NER_MODEL_DIR}"
                           PA_NER_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/ner")
if(PA_WITH_VAULT)
  target_link_libraries(ner_measure PRIVATE prompt_airlock_vault_client)
  target_compile_definitions(ner_measure PRIVATE PA_MEASURE_WITH_VAULT
    "PA_VAULT_EXE=\"${CMAKE_BINARY_DIR}/cargo/release/prompt-airlock-vault${CMAKE_EXECUTABLE_SUFFIX}\"")
  add_dependencies(ner_measure prompt_airlock_vault)
endif()
pa_copy_runtime_dlls(ner_measure)

# 문장 단위 민감정보 기준선(Phase 7.5-1). 합성 문장 셋과 NER 모델이 필요하다.
add_executable(sentence_measure EXCLUDE_FROM_ALL sentence_measure.cpp)
target_link_libraries(sentence_measure PRIVATE prompt_airlock_ner prompt_airlock_detect pa_options nlohmann_json::nlohmann_json)
target_compile_definitions(sentence_measure PRIVATE PA_NER_MODEL_DIR="${PA_NER_MODEL_DIR}"
                           PA_NER_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/ner"
                           PA_SENTENCE_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/sentence")
pa_copy_runtime_dlls(sentence_measure)

# HTTP 로 끝까지 지연·처리량(Phase 8a). 실제 Vault 와 NER 모델, 같은 프로세스의 mock provider 를 쓴다.
if(PA_WITH_VAULT)
  add_executable(gateway_measure EXCLUDE_FROM_ALL gateway_measure.cpp)
  target_link_libraries(gateway_measure PRIVATE prompt_airlock_gateway prompt_airlock_provider prompt_airlock_tls
                        prompt_airlock_vault_client prompt_airlock_ner pa_mock_provider pa_test_cert pa_options
                        nlohmann_json::nlohmann_json)
  target_compile_definitions(gateway_measure PRIVATE PA_NER_MODEL_DIR="${PA_NER_MODEL_DIR}"
    "PA_VAULT_EXE=\"${CMAKE_BINARY_DIR}/cargo/release/prompt-airlock-vault${CMAKE_EXECUTABLE_SUFFIX}\"")
  add_dependencies(gateway_measure prompt_airlock_vault)
  pa_copy_runtime_dlls(gateway_measure)
endif()
