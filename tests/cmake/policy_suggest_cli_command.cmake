if(NOT DEFINED PA_APP OR NOT EXISTS "${PA_APP}")
  message(FATAL_ERROR "policy_suggest_app_missing")
endif()
if(NOT DEFINED PA_TEST_DIR)
  message(FATAL_ERROR "policy_suggest_test_directory_missing")
endif()

file(MAKE_DIRECTORY "${PA_TEST_DIR}")
set(documents "${PA_TEST_DIR}/documents")
file(MAKE_DIRECTORY "${documents}/nested")
string(REPEAT "가" 33 long_value)
string(REPEAT "x" 129 long_byte_value)
string(ASCII 1 control)
string(ASCII 226 128 168 line_separator)
file(WRITE "${documents}/normal.txt" [=[사업명: 한빛안전데이터플랫폼
사업명: 010-2345-6789
사업명: ]=])
file(APPEND "${documents}/normal.txt" "${long_value}\n사업명: ${long_byte_value}\n사업명: bad${control}value\n사업명: before${line_separator}after\n사업명: 강서하님께서승인하셨습니다.\n")
file(WRITE "${documents}/duplicate.txt" [=[사업명: 한빛안전데이터플랫폼
과제명: 차세대환경정보화과제
]=])
file(WRITE "${documents}/nested/ignored.txt" "사업명: nestedonlycandidate\n")
file(WRITE "${PA_TEST_DIR}/outside.txt" "사업명: outsideonlycandidate\n")

get_filename_component(app_directory "${PA_APP}" DIRECTORY)
if(WIN32)
  set(pandoc "${app_directory}/pandoc.exe")
else()
  set(pandoc "${app_directory}/pandoc")
endif()
set(expected_unsupported 0)
set(expected_state "complete")
if(NOT EXISTS "${pandoc}")
  file(WRITE "${documents}/unsupported.tex" [=[\section{Synthetic unsupported markup}
]=])
  set(expected_unsupported 1)
  set(expected_state "partial_unsupported")
endif()

file(SHA256 "${documents}/normal.txt" normal_before)
file(SHA256 "${documents}/duplicate.txt" duplicate_before)
if(UNIX)
  file(CHMOD "${documents}" PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()
execute_process(
  COMMAND "${PA_APP}" policy suggest "${documents}"
  ENCODING UTF-8
  RESULT_VARIABLE suggest_status
  OUTPUT_VARIABLE suggest_stdout
  ERROR_VARIABLE suggest_stderr)
if(UNIX)
  file(CHMOD "${documents}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()
if(NOT suggest_status EQUAL 0)
  message(FATAL_ERROR "policy_suggest_normal_exit")
endif()
set(suggest_output "${suggest_stdout}${suggest_stderr}")
set(expected_index 0)
foreach(expected IN ITEMS "state=${expected_state}" "candidate: 한빛안전데이터플랫폼" "candidate: 차세대환경정보화과제"
                          "directories_skipped=1" "duplicates=1" "too_long=2" "invalid_rejected=2"
                          "sensitive_rejected=2" "review_required=true applied=false")
  math(EXPR expected_index "${expected_index}+1")
  string(FIND "${suggest_output}" "${expected}" found)
  if(found EQUAL -1)
    message(FATAL_ERROR "policy_suggest_expected_output_${expected_index}")
  endif()
endforeach()
if(NOT expected_unsupported EQUAL 0)
  string(FIND "${suggest_output}" "unsupported=1" unsupported_found)
  if(unsupported_found EQUAL -1)
    message(FATAL_ERROR "policy_suggest_unsupported_count")
  endif()
endif()
foreach(forbidden IN ITEMS "${documents}" "normal.txt" "duplicate.txt" "ignored.txt" "outside.txt"
                           "010-2345-6789" "nestedonlycandidate" "outsideonlycandidate" "강서하" "badvalue")
  string(FIND "${suggest_output}" "${forbidden}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "policy_suggest_output_redaction")
  endif()
endforeach()
file(SHA256 "${documents}/normal.txt" normal_after)
file(SHA256 "${documents}/duplicate.txt" duplicate_after)
if(NOT normal_before STREQUAL normal_after OR NOT duplicate_before STREQUAL duplicate_after)
  message(FATAL_ERROR "policy_suggest_modified_input")
endif()

set(limit_dir "${PA_TEST_DIR}/entry-limit")
file(MAKE_DIRECTORY "${limit_dir}")
foreach(index RANGE 1 65)
  file(WRITE "${limit_dir}/entry-${index}.txt" "")
endforeach()
execute_process(
  COMMAND "${PA_APP}" policy suggest "${limit_dir}"
  ENCODING UTF-8
  RESULT_VARIABLE limit_status
  OUTPUT_VARIABLE limit_stdout
  ERROR_VARIABLE limit_stderr)
if(NOT limit_status EQUAL 1 OR NOT limit_stdout STREQUAL "")
  message(FATAL_ERROR "policy_suggest_entry_limit_exit")
endif()
string(FIND "${limit_stderr}" "entry_limit" entry_limit_found)
if(entry_limit_found EQUAL -1)
  message(FATAL_ERROR "policy_suggest_entry_limit_code")
endif()
foreach(forbidden IN ITEMS "${limit_dir}" "entry-1.txt")
  string(FIND "${limit_stdout}${limit_stderr}" "${forbidden}" found)
  if(NOT found EQUAL -1)
    message(FATAL_ERROR "policy_suggest_limit_path_redaction")
  endif()
endforeach()

set(candidate_limit_dir "${PA_TEST_DIR}/candidate-limit")
file(MAKE_DIRECTORY "${candidate_limit_dir}")
set(many_candidates "")
foreach(index RANGE 0 256)
  string(APPEND many_candidates "사업명: synthetic-candidate-${index}\n")
endforeach()
file(WRITE "${candidate_limit_dir}/many.txt" "${many_candidates}")
execute_process(
  COMMAND "${PA_APP}" policy suggest "${candidate_limit_dir}"
  ENCODING UTF-8
  RESULT_VARIABLE candidate_limit_status
  OUTPUT_VARIABLE candidate_limit_stdout
  ERROR_VARIABLE candidate_limit_stderr)
if(NOT candidate_limit_status EQUAL 1 OR NOT candidate_limit_stdout STREQUAL "")
  message(FATAL_ERROR "policy_suggest_candidate_limit_exit")
endif()
string(FIND "${candidate_limit_stderr}" "candidate_limit" candidate_limit_found)
if(candidate_limit_found EQUAL -1)
  message(FATAL_ERROR "policy_suggest_candidate_limit_code")
endif()
string(FIND "${candidate_limit_stdout}${candidate_limit_stderr}" "${candidate_limit_dir}" candidate_path_found)
if(NOT candidate_path_found EQUAL -1)
  message(FATAL_ERROR "policy_suggest_candidate_limit_path_redaction")
endif()

if(UNIX)
  set(outside_link "${documents}/outside-link.txt")
  file(CREATE_LINK "${PA_TEST_DIR}/outside.txt" "${outside_link}" SYMBOLIC RESULT link_result)
  if(link_result STREQUAL "0")
    execute_process(
      COMMAND "${PA_APP}" policy suggest "${documents}"
      ENCODING UTF-8
      RESULT_VARIABLE link_status
      OUTPUT_VARIABLE link_stdout
      ERROR_VARIABLE link_stderr)
    if(NOT link_status EQUAL 1 OR NOT link_stdout STREQUAL "")
      message(FATAL_ERROR "policy_suggest_symlink_exit")
    endif()
    string(FIND "${link_stderr}" "path_boundary" boundary_found)
    if(boundary_found EQUAL -1)
      message(FATAL_ERROR "policy_suggest_symlink_code")
    endif()
    foreach(forbidden IN ITEMS "${documents}" "outsideonlycandidate")
      string(FIND "${link_stdout}${link_stderr}" "${forbidden}" found)
      if(NOT found EQUAL -1)
        message(FATAL_ERROR "policy_suggest_symlink_redaction")
      endif()
    endforeach()
  endif()
endif()

file(REMOVE_RECURSE "${PA_TEST_DIR}")
