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
