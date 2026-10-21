// 요청 JSON 읽기: 아무 바이트를 넣어도 죽지 않고, 받아들인 요청은 다시 읽어도 같은 결과다.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "prompt_airlock/gateway/request_json.hpp"

namespace gw = prompt_airlock::gateway;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view body(reinterpret_cast<const char*>(data), size);
    const auto first = gw::parse_request(body);
    const auto second = gw::parse_request(body);
    if (first.has_value() != second.has_value()) {
        __builtin_trap();
    }
    if (!first) {
        if (first.error().code() != second.error().code()) {
            __builtin_trap();
        }
        return 0;
    }
    if (first->document.segments().size() != second->document.segments().size() ||
        first->document.total_bytes() != second->document.total_bytes()) {
        __builtin_trap();
    }
    return 0;
}
