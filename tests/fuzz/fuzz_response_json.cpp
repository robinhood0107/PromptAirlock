// provider 응답 읽기: 아무 바이트를 넣어도 죽지 않고, 같은 입력은 같은 결과다.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "prompt_airlock/gateway/response_json.hpp"

namespace gw = prompt_airlock::gateway;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view body(reinterpret_cast<const char*>(data), size);
    const auto first = gw::parse_provider_answer(body);
    const auto second = gw::parse_provider_answer(body);
    if (first.has_value() != second.has_value()) {
        __builtin_trap();
    }
    if (first ? first->content.view() != second->content.view() || first->finish_reason != second->finish_reason
              : first.error() != second.error()) {
        __builtin_trap();
    }
    return 0;
}
