#pragma once

// 반환한 view 가 인자나 *this 의 수명에 묶인다는 표시. clang 에서만 -Wdangling 경고를 낸다.
// gcc 는 이 속성을 모르면 경고하므로 빈 매크로로 둔다.
// 시험에서 속성이 경고의 원인인지 확인하려고 바깥에서 빈 값으로 미리 정의할 수 있다.
#ifndef PA_LIFETIMEBOUND
#  if defined(__has_cpp_attribute)
#    if __has_cpp_attribute(clang::lifetimebound)
#      define PA_LIFETIMEBOUND [[clang::lifetimebound]]
#    endif
#  endif
#endif
#ifndef PA_LIFETIMEBOUND
#  define PA_LIFETIMEBOUND
#endif
