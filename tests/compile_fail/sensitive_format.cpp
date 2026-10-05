// 원문 상자는 std::format 에 바로 넣을 수 없다(실수로 로그에 찍히지 않게).
#include "prompt_airlock/core/sensitive.hpp"

#include <format>
#include <string>

namespace pc = prompt_airlock::core;

std::string probe(const pc::SensitiveText& text) {
#if PA_CF_OK
    return std::format("{}", text.size());
#else
    return std::format("{}", text);
#endif
}
