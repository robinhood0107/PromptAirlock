# 고정 seed property 시험(seed·반복 수는 tests/support/prng.hpp).
foreach(name IN ITEMS
    core_merge_property_test
    core_utf8_property_test)
  pa_add_gtest(${name} ${name}.cpp)
  target_link_libraries(${name} PRIVATE prompt_airlock_core pa_test_support)
endforeach()
