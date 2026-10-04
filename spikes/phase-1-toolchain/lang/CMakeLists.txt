pa_add_gtest(lang_value_category_test value_category_test.cpp)
pa_add_gtest(lang_string_view_test string_view_test.cpp)
pa_add_gtest(lang_expected_concepts_test expected_concepts_test.cpp)

# 원본보다 오래 사는 string_view 결함 예제. ASan 빌드에서만 검출을 시험한다.
add_executable(lang_dangling_view_demo dangling_view_demo.cpp)
target_link_libraries(lang_dangling_view_demo PRIVATE pa_options)
pa_copy_runtime_dlls(lang_dangling_view_demo)
if(PA_SANITIZE MATCHES "address")
  add_test(NAME lang_dangling_view_detected_by_asan COMMAND lang_dangling_view_demo)
  set_tests_properties(lang_dangling_view_detected_by_asan PROPERTIES
    PASS_REGULAR_EXPRESSION "AddressSanitizer: (heap-use-after-free|stack-use-after-scope|stack-use-after-return)")
endif()

# [[clang::lifetimebound]] 를 붙인 API 는 같은 실수를 컴파일 시점 경고로 잡는지 확인한다.
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  if(MSVC)
    set(PA_SYNTAX_ONLY /std:c++latest /Zs /EHsc)
  else()
    set(PA_SYNTAX_ONLY -std=c++23 -fsyntax-only)
  endif()
  add_test(NAME lang_lifetimebound_warns
    COMMAND "${CMAKE_CXX_COMPILER}" ${PA_SYNTAX_ONLY} "${CMAKE_CURRENT_SOURCE_DIR}/lifetimebound_warning.cpp")
  set_tests_properties(lang_lifetimebound_warns PROPERTIES PASS_REGULAR_EXPRESSION "-Wdangling")
endif()
