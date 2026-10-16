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
pa_add_compile_fail(entity_span_direct entity_span_direct.cpp
  "EntitySpan[^\n]*private|private[^\n]*EntitySpan")

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

# 단계 타입과 provider 입구(invariant 1, 2)
# 진단에 원래 단계 타입과 VerifiedPrompt 가 함께 나와야 통과한다(clang 과 gcc 는 순서가 반대다).
foreach(pair IN ITEMS raw:RawPrompt policy_checked:PolicyCheckedPrompt protected:ProtectedPrompt)
  string(REPLACE ":" ";" pair "${pair}")
  list(GET pair 0 stage)
  list(GET pair 1 type)
  pa_add_compile_fail(provider_from_${stage} provider_from_${stage}.cpp
    "(no viable conversion|invalid initialization)[^\n]*(${type}[^\n]*VerifiedPrompt|VerifiedPrompt[^\n]*${type})")
endforeach()
pa_add_compile_fail(verified_copy verified_copy.cpp
  "VerifiedPrompt[^\n]*delete|delete[^\n]*VerifiedPrompt")
pa_add_compile_fail(verified_direct verified_direct.cpp
  "no matching (constructor|function)[^\n]*VerifiedPrompt")
pa_add_compile_fail(state_key_forge state_key_forge.cpp
  "StateKey[^\n]*private|private[^\n]*StateKey")

# 연구용 열쇠(invariant 12)
pa_add_compile_fail(no_protection_without_key no_protection_without_key.cpp
  "ResearchOnly[^\n]*private|private[^\n]*ResearchOnly")
pa_add_compile_fail(research_key_without_define research_key_without_define.cpp
  "make_research_only")
