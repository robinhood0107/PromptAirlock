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
    detect_credentials_test
    detect_encoded_test
    detect_evasion_test
    detect_formats_test
    detect_kr_accounts_test
    detect_pipeline_test
    detect_scan_test
    detect_sensitive_test
    detect_view_test)
  pa_add_gtest(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE prompt_airlock_detect pa_test_support)
endforeach()

