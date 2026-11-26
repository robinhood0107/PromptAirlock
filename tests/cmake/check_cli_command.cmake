if(NOT DEFINED PA_APP OR NOT EXISTS "${PA_APP}")
  message(FATAL_ERROR "check_app_missing")
endif()
if(NOT DEFINED PA_TEST_DIR)
  message(FATAL_ERROR "check_test_directory_missing")
endif()

file(MAKE_DIRECTORY "${PA_TEST_DIR}")
set(invalid_config "${PA_TEST_DIR}/invalid.json")
file(WRITE "${invalid_config}" [=[
{
  "listen": {
    "address": "127.0.0.1",
    "port": 1,
    "certificate_chain": "cert.pem",
    "private_key": "key.pem"
  },
  "provider": {
    "url": "https://127.0.0.1/v1/chat/completions",
    "credential_file": "credential",
    "model": "synthetic",
    "CHECK_COMMAND_SENTINEL": "CHECK_COMMAND_SENTINEL"
  },
  "origins": [{
    "name": "test",
    "token_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "grade_policy": "o-only"
  }]
}
]=])

execute_process(
  COMMAND "${PA_APP}" check "${invalid_config}"
  RESULT_VARIABLE invalid_status
  OUTPUT_VARIABLE invalid_stdout
  ERROR_VARIABLE invalid_stderr)
if(NOT invalid_status EQUAL 1)
  message(FATAL_ERROR "check_invalid_exit")
endif()
if(NOT invalid_stderr MATCHES "check: failed stage=config code=invalid")
  message(FATAL_ERROR "check_invalid_code")
endif()
set(invalid_output "${invalid_stdout}${invalid_stderr}")
foreach(forbidden IN ITEMS "CHECK_COMMAND_SENTINEL" "${PA_TEST_DIR}" "${PA_APP}")
  string(FIND "${invalid_output}" "${forbidden}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "check_invalid_output_redaction")
  endif()
endforeach()

execute_process(
  COMMAND "${PA_APP}" check
  RESULT_VARIABLE usage_status
  OUTPUT_VARIABLE usage_stdout
  ERROR_VARIABLE usage_stderr)
if(NOT usage_status EQUAL 2)
  message(FATAL_ERROR "check_usage_exit")
endif()
set(usage_output "${usage_stdout}${usage_stderr}")
string(FIND "${usage_output}" "prompt-airlock check <config.json>" usage_found)
if(usage_found EQUAL -1)
  message(FATAL_ERROR "check_usage_line")
endif()
