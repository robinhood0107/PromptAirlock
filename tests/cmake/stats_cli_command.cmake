if(NOT DEFINED PA_APP OR NOT EXISTS "${PA_APP}")
  message(FATAL_ERROR "stats_app_missing")
endif()
if(NOT DEFINED PA_STATS_FIXTURE OR NOT EXISTS "${PA_STATS_FIXTURE}")
  message(FATAL_ERROR "stats_fixture_missing")
endif()
if(NOT DEFINED PA_TEST_DIR)
  message(FATAL_ERROR "stats_test_directory_missing")
endif()

string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef test_id)
set(test_root "${PA_TEST_DIR}/${test_id}")
file(MAKE_DIRECTORY "${test_root}")

set(missing_dir "${test_root}/missing")
execute_process(
  COMMAND "${PA_APP}" stats "${missing_dir}"
  RESULT_VARIABLE missing_status
  OUTPUT_VARIABLE missing_stdout
  ERROR_VARIABLE missing_stderr)
if(NOT missing_status EQUAL 0 OR NOT missing_stdout MATCHES "stats: state=missing scope=none")
  message(FATAL_ERROR "stats_missing_result")
endif()
if(EXISTS "${missing_dir}")
  message(FATAL_ERROR "stats_missing_created_directory")
endif()

set(empty_dir "${test_root}/empty")
file(MAKE_DIRECTORY "${empty_dir}")
execute_process(
  COMMAND "${PA_APP}" stats "${empty_dir}"
  RESULT_VARIABLE empty_status
  OUTPUT_VARIABLE empty_stdout
  ERROR_VARIABLE empty_stderr)
if(NOT empty_status EQUAL 0 OR NOT empty_stdout MATCHES "stats: state=empty scope=none requests=0 normal=0 blocked=0 confirmation=0 failure=0")
  message(FATAL_ERROR "stats_empty_result")
endif()
file(GLOB empty_files "${empty_dir}/*")
if(empty_files)
  message(FATAL_ERROR "stats_empty_wrote_files")
endif()

set(valid_dir "${test_root}/valid")
execute_process(
  COMMAND "${PA_STATS_FIXTURE}" "${valid_dir}"
  RESULT_VARIABLE fixture_status
  OUTPUT_VARIABLE fixture_stdout
  ERROR_VARIABLE fixture_stderr)
if(NOT fixture_status EQUAL 0)
  message(FATAL_ERROR "stats_fixture_failed")
endif()
file(GLOB before_files "${valid_dir}/*")
list(SORT before_files)
set(before_hashes "")
foreach(path IN LISTS before_files)
  file(SHA256 "${path}" hash)
  list(APPEND before_hashes "${path}=${hash}")
endforeach()
execute_process(
  COMMAND "${PA_APP}" stats "${valid_dir}"
  RESULT_VARIABLE valid_status
  OUTPUT_VARIABLE valid_stdout
  ERROR_VARIABLE valid_stderr)
if(NOT valid_status EQUAL 0)
  message(FATAL_ERROR "stats_valid_exit")
endif()
string(FIND "${valid_stdout}" "stats: state=ok scope=recent_24h coverage=complete requests=5 normal=1 blocked=2 confirmation=1 failure=1" valid_summary)
if(valid_summary EQUAL -1)
  message(FATAL_ERROR "stats_valid_counts")
endif()
set(valid_output "${valid_stdout}${valid_stderr}")
foreach(forbidden IN ITEMS "${valid_dir}" "SYNTHETIC_EGRESS_BODY" "SYNTHETIC_RESPONSE")
  string(FIND "${valid_output}" "${forbidden}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "stats_valid_output_redaction")
  endif()
endforeach()
file(GLOB after_files "${valid_dir}/*")
list(SORT after_files)
set(after_hashes "")
foreach(path IN LISTS after_files)
  file(SHA256 "${path}" hash)
  list(APPEND after_hashes "${path}=${hash}")
endforeach()
if(NOT before_files STREQUAL after_files OR NOT before_hashes STREQUAL after_hashes)
  message(FATAL_ERROR "stats_modified_audit_files")
endif()

set(corrupt_dir "${test_root}/corrupt")
file(MAKE_DIRECTORY "${corrupt_dir}")
file(COPY "${valid_dir}/" DESTINATION "${corrupt_dir}")
file(GLOB corrupt_files "${corrupt_dir}/audit-*.jsonl")
list(LENGTH corrupt_files corrupt_count)
if(NOT corrupt_count EQUAL 1)
  message(FATAL_ERROR "stats_corrupt_fixture_shape")
endif()
list(GET corrupt_files 0 corrupt_file)
file(APPEND "${corrupt_file}" "x")
execute_process(
  COMMAND "${PA_APP}" stats "${corrupt_dir}"
  RESULT_VARIABLE corrupt_status
  OUTPUT_VARIABLE corrupt_stdout
  ERROR_VARIABLE corrupt_stderr)
if(NOT corrupt_status EQUAL 1 OR NOT corrupt_stderr MATCHES "stats: failed stage=verify code=corrupt")
  message(FATAL_ERROR "stats_corrupt_result")
endif()
if(corrupt_stdout MATCHES "requests=" OR corrupt_stderr MATCHES "${corrupt_dir}")
  message(FATAL_ERROR "stats_corrupt_output_redaction")
endif()

set(partial_dir "${test_root}/partial")
execute_process(
  COMMAND "${PA_STATS_FIXTURE}" "${partial_dir}" partial
  RESULT_VARIABLE partial_fixture_status
  OUTPUT_VARIABLE partial_fixture_stdout
  ERROR_VARIABLE partial_fixture_stderr)
if(NOT partial_fixture_status EQUAL 0)
  message(FATAL_ERROR "stats_partial_fixture_failed")
endif()
execute_process(
  COMMAND "${PA_APP}" stats "${partial_dir}"
  RESULT_VARIABLE partial_status
  OUTPUT_VARIABLE partial_stdout
  ERROR_VARIABLE partial_stderr)
if(NOT partial_status EQUAL 1 OR NOT partial_stderr MATCHES "stats: failed state=partial scope=recent_24h_limited stage=read code=range_limited")
  message(FATAL_ERROR "stats_partial_result")
endif()
if(partial_stdout MATCHES "requests=" OR partial_stderr MATCHES "${partial_dir}")
  message(FATAL_ERROR "stats_partial_output_redaction")
endif()
