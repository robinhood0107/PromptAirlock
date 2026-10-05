#pragma once

// 반환한 view 가 인자나 *this 의 수명에 묶인다는 표시. clang 에서만 -Wdangling 경고를 낸다.
// gcc 는 이 속성을 모르면 경고하므로 빈 매크로로 둔다.
#if defined(__has_cpp_attribute)
#  if __has_cpp_attribute(clang::lifetimebound)
#    define PA_LIFETIMEBOUND [[clang::lifetimebound]]
#  endif
#endif
#ifndef PA_LIFETIMEBOUND
#  define PA_LIFETIMEBOUND
#endif
