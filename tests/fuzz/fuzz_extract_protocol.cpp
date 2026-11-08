#include <cstddef>
#include <cstdint>
#include <string_view>

#include "prompt_airlock/extract/runner.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace ex = prompt_airlock::extract;
    const auto result = ex::from_json(std::string_view(reinterpret_cast<const char*>(data), size));
    if (!result) return 0;
    const auto again = ex::from_json(ex::to_json(*result));
    if (!again || result->has_value() != again->has_value()) __builtin_trap();
    if (*result) {
        if ((**result).blocks != (**again).blocks || (**result).documents != (**again).documents ||
            (**result).omitted != (**again).omitted || (**result).format != (**again).format) __builtin_trap();
    } else if (result->error() != again->error()) __builtin_trap();
    return 0;
}
