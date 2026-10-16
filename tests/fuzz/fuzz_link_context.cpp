// 링크 위치 판정이 아무 응답에도 죽지 않고, 결정적이며, 선형 시간(-timeout)인지 본다.
// 입력 끝에 합성 token 하나를 붙여 판정할 token 이 늘 있게 한다.
#include "prompt_airlock/core/link_context.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace pc = prompt_airlock::core;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string response(reinterpret_cast<const char*>(data), size);
    response += "\xE2\x9F\xA6PERSON_7Q2MK4XD9A\xE2\x9F\xA7";
    const auto tokens = pc::scan_tokens(response);
    const auto first = pc::classify_link_contexts(response, tokens);
    const auto second = pc::classify_link_contexts(response, tokens);
    if (first != second || first.size() != tokens.size() || tokens.empty()) {
        __builtin_trap();
    }
    (void)pc::check_link_contexts(response, tokens);
    return 0;
}
