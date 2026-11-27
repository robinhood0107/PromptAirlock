if(NOT DEFINED PA_APP OR NOT EXISTS "${PA_APP}")
  message(FATAL_ERROR "keys_app_missing")
endif()
if(NOT DEFINED PA_TEST_DIR)
  message(FATAL_ERROR "keys_test_directory_missing")
endif()

file(MAKE_DIRECTORY "${PA_TEST_DIR}")
set(config "${PA_TEST_DIR}/gateway.json")
file(WRITE "${config}" [=[
{
  "listen": {
    "address": "127.0.0.1",
    "port": 8443,
    "certificate_chain": "certs/server.pem",
    "private_key": "certs/server.key"
  },
  "provider": {
    "url": "https://127.0.0.1:9443/v1/chat/completions",
    "credential_file": "secrets/provider.key",
    "trust_file": "certs/mock-ca.pem",
    "model": "synthetic-model",
    "credential_rotation_origin": "service-b"
  },
  "origins": [
    { "name": "admin-console", "token_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "grade_policy": "declare" },
    { "name": "service-a", "token_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "grade_policy": "o-only" },
    { "name": "service-b", "token_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "grade_policy": "declare" }
  ],
  "admin_history_origin": "admin-console",
  "internal_terms": ["synthetic-term"],
  "output_token_cap": 2048
}
]=])

file(SHA256 "${config}" before_list_hash)
execute_process(
  COMMAND "${PA_APP}" keys list "${config}"
  RESULT_VARIABLE list_status
  OUTPUT_VARIABLE list_stdout
  ERROR_VARIABLE list_stderr)
if(NOT list_status EQUAL 0)
  message(FATAL_ERROR "keys_list_exit")
endif()
set(list_output "${list_stdout}${list_stderr}")
foreach(expected IN ITEMS "admin-console declare" "service-a o-only" "service-b declare")
  string(FIND "${list_output}" "${expected}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "keys_list_fields")
  endif()
endforeach()
file(SHA256 "${config}" after_list_hash)
if(NOT before_list_hash STREQUAL after_list_hash)
  message(FATAL_ERROR "keys_list_modified_config")
endif()
foreach(forbidden IN ITEMS "${PA_TEST_DIR}" "token_sha256" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
  string(FIND "${list_output}" "${forbidden}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "keys_list_redaction")
  endif()
endforeach()

execute_process(
  COMMAND "${PA_APP}" keys add "${config}" "sample-origin"
  RESULT_VARIABLE add_status
  OUTPUT_VARIABLE add_stdout
  ERROR_VARIABLE add_stderr)
if(NOT add_status EQUAL 0)
  message(FATAL_ERROR "keys_add_exit")
endif()
string(REGEX MATCHALL "token: [A-Za-z0-9_-]+" token_lines "${add_stdout}")
list(LENGTH token_lines token_count)
if(NOT token_count EQUAL 1)
  message(FATAL_ERROR "keys_add_token_count")
endif()
string(REGEX REPLACE "^token: " "" synthetic_token "${token_lines}")
string(LENGTH "${synthetic_token}" token_length)
if(NOT token_length EQUAL 43)
  message(FATAL_ERROR "keys_add_token_format")
endif()
string(SHA256 synthetic_token_sha256 "${synthetic_token}")
file(READ "${config}" after_add)
string(FIND "${after_add}" "${synthetic_token_sha256}" hash_found)
string(FIND "${after_add}" "${synthetic_token}" raw_token_found)
if(hash_found EQUAL -1 OR NOT raw_token_found EQUAL -1)
  message(FATAL_ERROR "keys_add_storage")
endif()
set(add_output "${add_stdout}${add_stderr}")
foreach(forbidden IN ITEMS "${PA_TEST_DIR}" "${PA_APP}" "token_sha256")
  string(FIND "${add_output}" "${forbidden}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "keys_add_output")
  endif()
endforeach()
string(FIND "${add_stderr}" "${synthetic_token}" leaked_token)
if(NOT leaked_token EQUAL -1)
  message(FATAL_ERROR "keys_add_stderr_secret")
endif()

file(SHA256 "${config}" before_list_after_add_hash)
execute_process(
  COMMAND "${PA_APP}" keys list "${config}"
  RESULT_VARIABLE updated_list_status
  OUTPUT_VARIABLE updated_list_stdout
  ERROR_VARIABLE updated_list_stderr)
if(NOT updated_list_status EQUAL 0)
  message(FATAL_ERROR "keys_updated_list_exit")
endif()
set(updated_list "${updated_list_stdout}${updated_list_stderr}")
string(FIND "${updated_list}" "sample-origin o-only" added_default_found)
if(added_default_found EQUAL -1)
  message(FATAL_ERROR "keys_default_grade")
endif()
file(SHA256 "${config}" after_updated_list_hash)
if(NOT before_list_after_add_hash STREQUAL after_updated_list_hash)
  message(FATAL_ERROR "keys_updated_list_modified_config")
endif()
foreach(forbidden IN ITEMS "${PA_TEST_DIR}" "${synthetic_token}" "${synthetic_token_sha256}")
  string(FIND "${updated_list}" "${forbidden}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "keys_updated_list_redaction")
  endif()
endforeach()

execute_process(
  COMMAND "${PA_APP}" keys add "${config}" "declared-origin" declare
  RESULT_VARIABLE declared_status
  OUTPUT_VARIABLE declared_stdout
  ERROR_VARIABLE declared_stderr)
if(NOT declared_status EQUAL 0)
  message(FATAL_ERROR "keys_declared_add_exit")
endif()
string(REGEX MATCHALL "token: [A-Za-z0-9_-]+" declared_tokens "${declared_stdout}")
list(LENGTH declared_tokens declared_token_count)
if(NOT declared_token_count EQUAL 1)
  message(FATAL_ERROR "keys_declared_token_count")
endif()

file(SHA256 "${config}" before_duplicate_hash)
execute_process(
  COMMAND "${PA_APP}" keys add "${config}" "sample-origin"
  RESULT_VARIABLE duplicate_status
  OUTPUT_VARIABLE duplicate_stdout
  ERROR_VARIABLE duplicate_stderr)
if(NOT duplicate_status EQUAL 1 OR NOT duplicate_stdout STREQUAL "")
  message(FATAL_ERROR "keys_duplicate_exit")
endif()
string(FIND "${duplicate_stderr}" "duplicate" duplicate_code_found)
if(duplicate_code_found EQUAL -1)
  message(FATAL_ERROR "keys_duplicate_code")
endif()
file(SHA256 "${config}" after_duplicate_hash)
if(NOT before_duplicate_hash STREQUAL after_duplicate_hash)
  message(FATAL_ERROR "keys_duplicate_modified_config")
endif()

foreach(reference IN ITEMS "admin-console" "service-b")
  file(SHA256 "${config}" before_reference_hash)
  execute_process(
    COMMAND "${PA_APP}" keys revoke "${config}" "${reference}"
    RESULT_VARIABLE reference_status
    OUTPUT_VARIABLE reference_stdout
    ERROR_VARIABLE reference_stderr)
  if(NOT reference_status EQUAL 1 OR NOT reference_stdout STREQUAL "")
    message(FATAL_ERROR "keys_reference_exit")
  endif()
  string(FIND "${reference_stderr}" "origin_in_use" reference_code_found)
  if(reference_code_found EQUAL -1)
    message(FATAL_ERROR "keys_reference_code")
  endif()
  file(SHA256 "${config}" after_reference_hash)
  if(NOT before_reference_hash STREQUAL after_reference_hash)
    message(FATAL_ERROR "keys_reference_modified_config")
  endif()
endforeach()

execute_process(
  COMMAND "${PA_APP}" keys revoke "${config}" "sample-origin"
  RESULT_VARIABLE revoke_status
  OUTPUT_VARIABLE revoke_stdout
  ERROR_VARIABLE revoke_stderr)
if(NOT revoke_status EQUAL 0 OR NOT revoke_stderr STREQUAL "")
  message(FATAL_ERROR "keys_revoke_exit")
endif()
string(FIND "${revoke_stdout}" "revoked" revoke_message_found)
if(revoke_message_found EQUAL -1)
  message(FATAL_ERROR "keys_revoke_message")
endif()
execute_process(
  COMMAND "${PA_APP}" keys list "${config}"
  RESULT_VARIABLE final_list_status
  OUTPUT_VARIABLE final_list_stdout
  ERROR_VARIABLE final_list_stderr)
if(NOT final_list_status EQUAL 0)
  message(FATAL_ERROR "keys_final_list_exit")
endif()
string(FIND "${final_list_stdout}" "sample-origin" revoked_origin_found)
if(NOT revoked_origin_found EQUAL -1)
  message(FATAL_ERROR "keys_revoke_not_applied")
endif()

set(last_config "${PA_TEST_DIR}/last-origin.json")
file(WRITE "${last_config}" [=[
{
  "listen": { "address": "127.0.0.1", "port": 8443, "certificate_chain": "cert.pem", "private_key": "key.pem" },
  "provider": { "url": "https://127.0.0.1:9443/v1/chat/completions", "credential_file": "provider.key", "model": "synthetic-model" },
  "origins": [{ "name": "only-origin", "token_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "grade_policy": "o-only" }],
  "internal_terms": []
}
]=])
file(SHA256 "${last_config}" before_last_hash)
execute_process(
  COMMAND "${PA_APP}" keys revoke "${last_config}" "only-origin"
  RESULT_VARIABLE last_status
  OUTPUT_VARIABLE last_stdout
  ERROR_VARIABLE last_stderr)
if(NOT last_status EQUAL 1 OR NOT last_stdout STREQUAL "")
  message(FATAL_ERROR "keys_last_origin_exit")
endif()
string(FIND "${last_stderr}" "last_origin" last_code_found)
if(last_code_found EQUAL -1)
  message(FATAL_ERROR "keys_last_origin_code")
endif()
file(SHA256 "${last_config}" after_last_hash)
if(NOT before_last_hash STREQUAL after_last_hash)
  message(FATAL_ERROR "keys_last_origin_modified_config")
endif()

set(concurrent_config "${PA_TEST_DIR}/concurrent.json")
file(WRITE "${concurrent_config}" [=[
{
  "listen": { "address": "127.0.0.1", "port": 8443, "certificate_chain": "cert.pem", "private_key": "key.pem" },
  "provider": { "url": "https://127.0.0.1:9443/v1/chat/completions", "credential_file": "provider.key", "model": "synthetic-model" },
  "origins": [{ "name": "initial-origin", "token_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "grade_policy": "o-only" }],
  "internal_terms": []
}
]=])
if(WIN32)
  execute_process(
    COMMAND powershell.exe -NoProfile -NonInteractive -File "${CMAKE_CURRENT_LIST_DIR}/keys_cli_concurrency.ps1"
      -App "${PA_APP}" -ConfigFile "${concurrent_config}"
    RESULT_VARIABLE concurrent_status
    OUTPUT_VARIABLE concurrent_stdout
    ERROR_VARIABLE concurrent_stderr)
else()
  execute_process(
    COMMAND bash "${CMAKE_CURRENT_LIST_DIR}/keys_cli_concurrency.sh" "${PA_APP}" "${concurrent_config}"
    RESULT_VARIABLE concurrent_status
    OUTPUT_VARIABLE concurrent_stdout
    ERROR_VARIABLE concurrent_stderr)
endif()
if(NOT concurrent_status EQUAL 0 OR NOT concurrent_stdout MATCHES "keys_process_concurrency=passed")
  message(FATAL_ERROR "keys_process_concurrency")
endif()
foreach(forbidden IN ITEMS "${PA_TEST_DIR}" "token:" "token_sha256")
  string(FIND "${concurrent_stdout}${concurrent_stderr}" "${forbidden}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "keys_process_concurrency_output")
  endif()
endforeach()
file(GLOB leftover_process_files
  "${PA_TEST_DIR}/keys-first.*"
  "${PA_TEST_DIR}/keys-first-error.*"
  "${PA_TEST_DIR}/keys-second.*"
  "${PA_TEST_DIR}/keys-second-error.*"
  "${PA_TEST_DIR}/keys-failure-error.*")
if(leftover_process_files)
  message(FATAL_ERROR "keys_process_temp_cleanup")
endif()

unset(synthetic_token)
unset(declared_tokens)
