pa_add_gtest(core_version_test core_version_test.cpp)
target_link_libraries(core_version_test PRIVATE prompt_airlock_core)
target_compile_definitions(core_version_test PRIVATE
  PA_PROJECT_VERSION="${PROJECT_VERSION}"
  PA_VAULT_PROTO="${PROJECT_SOURCE_DIR}/proto/vault_v1.proto")

# core 단위 시험: 파일 하나에 실행 파일 하나.
foreach(name IN ITEMS
    core_document_test
    core_encoded_test
    core_entity_test
    core_grade_test
    core_link_context_test
    core_merge_test
    core_offset_test
    core_particle_test
    core_pipeline_test
    core_policy_test
    core_prompt_test
    core_reason_test
    core_request_params_test
    core_restore_test
    core_sensitive_test
    core_sha256_test
    core_token_test
    core_types_test
    core_utf8_test)
  pa_add_gtest(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE prompt_airlock_core pa_test_support)
endforeach()

# 연구용 열쇠가 필요한 시험. 연구 라이브러리를 링크한다.
foreach(name IN ITEMS
    core_privacy_test
    core_strategy_test)
  pa_add_gtest(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE prompt_airlock_core_research pa_test_support)
endforeach()

# 탐지기 시험. 파이프라인 시험은 시험용 Vault(pa_test_support)를 쓴다.
foreach(name IN ITEMS
    detect_accounts_test
    detect_confidential_test
    detect_credentials_test
    detect_encoded_test
    detect_evasion_test
    detect_formats_test
    detect_institution_test
    detect_kr_accounts_test
    detect_ner_test
    detect_organization_test
    detect_pipeline_test
    detect_scan_test
    detect_sensitive_test
    detect_view_test)
  pa_add_gtest(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE prompt_airlock_detect pa_test_support)
endforeach()

# Vault 클라이언트 오류 대응표와 값 타입(실제 Vault 없이).
pa_add_gtest(vault_client_mapping_test vault_client_mapping_test.cpp)
target_link_libraries(vault_client_mapping_test PRIVATE prompt_airlock_vault_client)
pa_add_gtest(vault_client_types_test vault_client_types_test.cpp)
target_link_libraries(vault_client_types_test PRIVATE prompt_airlock_vault_client)

# NER 시험. 모델·tokenizer 는 CMake 가 빌드 디렉터리 models/ner/ 에 받아 둔다(없으면 시험이 실패한다).
find_package(nlohmann_json CONFIG REQUIRED)
foreach(name IN ITEMS
    ner_boundary_test
    ner_engine_test
    ner_fixture_test
    ner_model_files_test
    ner_pool_test
    ner_sentence_classifier_test
    ner_session_test
    ner_tokenizer_test
    ner_windows_test)
  pa_add_gtest(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE prompt_airlock_ner nlohmann_json::nlohmann_json)
  target_compile_definitions(${name} PRIVATE
    PA_NER_MODEL_DIR="${PA_NER_MODEL_DIR}"
    PA_NER_FIXTURE_DIR="${PROJECT_SOURCE_DIR}/tests/fixtures/ner")
endforeach()

# TLS 설정(ADR 0014). 시험 인증서는 실행 때마다 새로 만든다.
if(EXISTS "${PA_SENTENCE_MODEL_DIR}/classifier.json")
  target_compile_definitions(ner_sentence_classifier_test PRIVATE
    PA_TEST_SENTENCE_MODEL_DIR="${PA_SENTENCE_MODEL_DIR}")
endif()
pa_add_gtest(tls_context_test tls_context_test.cpp)
target_link_libraries(tls_context_test PRIVATE prompt_airlock_tls pa_test_cert)

# HTTP 입구: 설정, 출처 인증, 오류 응답.
foreach(name IN ITEMS
    gateway_auth_test
    gateway_config_test
    gateway_confirm_test
    gateway_error_body_test
    gateway_pipeline_test
    gateway_response_json_test
    gateway_request_json_test)
  pa_add_gtest(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE prompt_airlock_gateway pa_test_support pa_mock_provider nlohmann_json::nlohmann_json)
endforeach()
pa_add_gtest(gateway_server_test gateway_server_test.cpp)
target_link_libraries(gateway_server_test PRIVATE prompt_airlock_gateway prompt_airlock_tls pa_test_cert
                      nlohmann_json::nlohmann_json)

# provider HTTPS 클라이언트. 같은 프로세스에 mock provider 를 띄운다.
pa_add_gtest(provider_client_test provider_client_test.cpp)
target_link_libraries(provider_client_test PRIVATE prompt_airlock_provider prompt_airlock_tls pa_mock_provider pa_test_cert
                      nlohmann_json::nlohmann_json)

# 감사 기록(ADR 0021).
pa_add_gtest(audit_log_test audit_log_test.cpp)
target_link_libraries(audit_log_test PRIVATE prompt_airlock_audit)

# 문서 추출(ADR 0028). 해석 시험은 시험 안에서 libzip 으로 문서를 만든다.
find_package(libzip CONFIG REQUIRED)
pa_add_gtest(extract_test extract_test.cpp)
target_link_libraries(extract_test PRIVATE prompt_airlock_extract prompt_airlock_extract_client libzip::zip pa_test_support)
add_executable(extract_test_child extract_test_child.cpp)
target_link_libraries(extract_test_child PRIVATE pa_options)
pa_add_gtest(extract_runner_test extract_runner_test.cpp)
target_link_libraries(extract_runner_test PRIVATE prompt_airlock_extract_client)
target_compile_definitions(extract_runner_test PRIVATE "PA_TEST_CHILD=\"$<TARGET_FILE:extract_test_child>\""
                           "PA_EXTRACT_EXE=\"$<TARGET_FILE:prompt-airlock-extract>\"")
add_dependencies(extract_runner_test extract_test_child prompt-airlock-extract)
find_package(ZLIB REQUIRED)
pa_add_gtest(extract_hwp_test extract_hwp_test.cpp)
target_link_libraries(extract_hwp_test PRIVATE prompt_airlock_extract prompt_airlock_extract_client ZLIB::ZLIB pa_test_support)
pa_add_gtest(extract_pdf_test extract_pdf_test.cpp)
target_link_libraries(extract_pdf_test PRIVATE prompt_airlock_extract prompt_airlock_extract_client)
target_link_libraries(extract_pdf_test PRIVATE pa_test_support)
if(PA_WITH_PDFIUM)
  target_compile_definitions(extract_pdf_test PRIVATE PA_TEST_WITH_PDFIUM)
endif()
