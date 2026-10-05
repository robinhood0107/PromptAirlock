include(CompileFail)

# 위치 타입(ADR 0007, invariant 15)
pa_add_compile_fail(offset_mix_compare offset_mix_compare.cpp
  "(invalid operands|no match for).*Codepoint")
pa_add_compile_fail(offset_from_size_t offset_from_size_t.cpp
  "conversion from [^ ]*int[^ ]* to[^\n]*Utf8Byte")
pa_add_compile_fail(byte_span_from_codepoint byte_span_from_codepoint.cpp
  "(no viable conversion|cannot convert)[^\n]*Codepoint")
pa_add_compile_fail(byte_span_direct byte_span_direct.cpp
  "ByteSpan[^\n]*private|private[^\n]*ByteSpan")

# 원문 상자(spec §13)
pa_add_compile_fail(sensitive_copy sensitive_copy.cpp
  "SensitiveText[^\n]*delete|delete[^\n]*SensitiveText")
pa_add_compile_fail(sensitive_format sensitive_format.cpp
  "formatter|formattable|basic_format_arg")

# view 수명 표시가 실제로 경고를 만드는지 본다(clang 전용). 짝 시험은 속성을 빈 값으로 정의해
# 경고가 사라지는지 확인한다. 둘 다 통과해야 경고의 원인이 PA_LIFETIMEBOUND 이다.
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  if(MSVC)
    set(pa_syntax_only /std:c++latest /Zs /EHsc /utf-8 "-I${PROJECT_SOURCE_DIR}/include")
  else()
    set(pa_syntax_only -std=c++23 -fsyntax-only "-I${PROJECT_SOURCE_DIR}/include")
  endif()
  add_test(NAME lifetimebound_warns
    COMMAND "${CMAKE_CXX_COMPILER}" ${pa_syntax_only} "${CMAKE_CURRENT_SOURCE_DIR}/lifetimebound_view.cpp")
  set_tests_properties(lifetimebound_warns PROPERTIES
    PASS_REGULAR_EXPRESSION "-Wreturn-stack-address|-Wdangling")
  add_test(NAME lifetimebound_absent_no_warning
    COMMAND "${CMAKE_CXX_COMPILER}" ${pa_syntax_only} -DPA_LIFETIMEBOUND= "${CMAKE_CURRENT_SOURCE_DIR}/lifetimebound_view.cpp")
  set_tests_properties(lifetimebound_absent_no_warning PROPERTIES
    FAIL_REGULAR_EXPRESSION "-Wreturn-stack-address|-Wdangling")
endif()
