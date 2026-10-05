#pragma once

// property 시험용 결정적 난수. 표준 분포(uniform_int_distribution 등)는 구현마다 결과가 달라
// 쓰지 않는다. 같은 seed 면 Windows·Linux 에서 같은 입력이 나온다.
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace pa_test {

class SplitMix64 {
public:
    explicit SplitMix64(std::uint64_t seed) noexcept : state_(seed) {}

    std::uint64_t next() noexcept {
        std::uint64_t z = (state_ += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31U);
    }

    // [0, bound) 균등. 나머지 편향을 없애려고 거절 표본을 쓴다.
    std::uint64_t below(std::uint64_t bound) noexcept {
        if (bound <= 1) {
            return 0;
        }
        const std::uint64_t limit = (~std::uint64_t{0}) - ((~std::uint64_t{0}) % bound);
        std::uint64_t value = next();
        while (value >= limit) {
            value = next();
        }
        return value % bound;
    }

    bool chance(std::uint64_t numerator, std::uint64_t denominator) noexcept { return below(denominator) < numerator; }

private:
    std::uint64_t state_;
};

struct PropertyConfig {
    std::vector<std::uint64_t> seeds;
    std::size_t iterations;
};

namespace detail {

inline std::string read_env(const char* name) {
#if defined(_MSC_VER)
    char* value = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) {
        return {};
    }
    std::string out(value);
    std::free(value);
    return out;
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::string{} : std::string(value);
#endif
}

}  // namespace detail

// 고정 seed 3개 × 2000회. PA_PROPERTY_SEED, PA_PROPERTY_ITERATIONS 는 로컬 탐색용으로만 쓴다.
inline PropertyConfig property_config() {
    PropertyConfig config{{0x5EED202610050001ULL, 0x5EED202610050002ULL, 0x5EED202610050003ULL}, 2000};
    if (const auto seed = detail::read_env("PA_PROPERTY_SEED"); !seed.empty()) {
        config.seeds = {std::strtoull(seed.c_str(), nullptr, 0)};
    }
    if (const auto iterations = detail::read_env("PA_PROPERTY_ITERATIONS"); !iterations.empty()) {
        config.iterations = static_cast<std::size_t>(std::strtoull(iterations.c_str(), nullptr, 10));
    }
    return config;
}

}  // namespace pa_test
