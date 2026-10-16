# core 소스가 I/O·시계·난수·정규식·다른 모듈에 기대지 않는지 검사한다(ADR 0001).
# 사용: cmake -DPA_PURITY_ROOTS=<디렉터리;...> -P CheckCorePurity.cmake
# 위반이 하나라도 있으면 파일과 규칙 이름을 출력하고 실패한다. 원문 줄은 출력하지 않는다.
cmake_minimum_required(VERSION 3.28)

if(NOT PA_PURITY_ROOTS)
  message(FATAL_ERROR "PA_PURITY_ROOTS 가 비어 있다.")
endif()

# 규칙 이름과 정규식 쌍. CMake 정규식에는 \b 가 없어 앞뒤 문자 집합으로 경계를 표현한다.
set(_rules
  "include-iostream"   "#[ \t]*include[ \t]*<iostream>"
  "include-fstream"    "#[ \t]*include[ \t]*<fstream>"
  "include-cstdio"     "#[ \t]*include[ \t]*<(cstdio|stdio\\.h)>"
  "include-filesystem" "#[ \t]*include[ \t]*<filesystem>"
  "include-chrono"     "#[ \t]*include[ \t]*<(chrono|ctime|time\\.h)>"
  "include-thread"     "#[ \t]*include[ \t]*<(thread|mutex|condition_variable|future|stop_token)>"
  "include-random"     "#[ \t]*include[ \t]*<random>"
  "include-regex"      "#[ \t]*include[ \t]*<regex>"
  "include-os"         "#[ \t]*include[ \t]*<(windows\\.h|unistd\\.h|sys/)"
  "include-module"     "#[ \t]*include[ \t]*\"prompt_airlock/(detect|ner|vault_client|provider|gateway|audit|tls)/"
  "console-output"     "std::(cout|cerr|clog|print)"
  "c-io"               "(^|[^A-Za-z0-9_])(printf|fprintf|puts|fopen|fwrite|fread)[ \t]*\\("
  "environment"        "(^|[^A-Za-z0-9_])(getenv|_wgetenv|secure_getenv)[ \t]*\\("
  "process"            "(^|[^A-Za-z0-9_:])(system|popen|_popen|CreateProcess[AW]?)[ \t]*\\("
  "c-random"           "(^|[^A-Za-z0-9_])(rand|srand)[ \t]*\\(|random_device"
  "clock"              "(system_clock|steady_clock|high_resolution_clock|sleep_for|sleep_until)"
  "raw-new"            "(^|[^A-Za-z0-9_])new[ \t]+[A-Za-z_(]"
)

set(_all_files "")
foreach(_root IN LISTS PA_PURITY_ROOTS)
  file(GLOB_RECURSE _found LIST_DIRECTORIES false "${_root}/*.hpp" "${_root}/*.cpp" "${_root}/*.h")
  list(APPEND _all_files ${_found})
endforeach()

if(NOT _all_files)
  message(FATAL_ERROR "검사할 파일이 없다: ${PA_PURITY_ROOTS}")
endif()

set(_violations 0)
foreach(_file IN LISTS _all_files)
  file(READ "${_file}" _text)
  list(LENGTH _rules _count)
  math(EXPR _last "${_count} - 1")
  foreach(_i RANGE 0 ${_last} 2)
    math(EXPR _j "${_i} + 1")
    list(GET _rules ${_i} _name)
    list(GET _rules ${_j} _regex)
    if(_text MATCHES "${_regex}")
      message(SEND_ERROR "core purity: ${_name}: ${_file}")
      math(EXPR _violations "${_violations} + 1")
    endif()
  endforeach()
  # 연구용 열쇠는 research 디렉터리 밖에서 쓰지 않는다.
  if(NOT _file MATCHES "/research/" AND _text MATCHES "make_research_only[ \t]*\\(|PA_CORE_RESEARCH")
    if(NOT _file MATCHES "/research\\.hpp$")
      message(SEND_ERROR "core purity: research-outside: ${_file}")
      math(EXPR _violations "${_violations} + 1")
    endif()
  endif()
endforeach()

list(LENGTH _all_files _file_count)
if(_violations GREATER 0)
  message(FATAL_ERROR "core purity: 위반 ${_violations}건")
endif()
message(STATUS "core purity: 파일 ${_file_count}개, 위반 0")
