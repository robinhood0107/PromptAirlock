// 지역 원문 상자의 view 를 돌려주면 clang 이 경고해야 한다(PA_LIFETIMEBOUND).
// 이 파일은 -fsyntax-only 로만 검사한다.
#include "prompt_airlock/core/sensitive.hpp"

#include <string_view>

std::string_view leak_view() {
    const auto local = prompt_airlock::core::SensitiveText::copy_of("가상 값");
    return local.view();
}
