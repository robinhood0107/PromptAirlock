#include "prompt_airlock/core/utf8.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "prng.hpp"

namespace pc = prompt_airlock::core;

namespace {

void append_utf8(std::string& out, char32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// 유효한 코드포인트를 고른다. 대리 영역은 건너뛴다.
char32_t random_codepoint(pa_test::SplitMix64& rng) {
    switch (rng.below(4)) {
        case 0: return static_cast<char32_t>(rng.below(0x80));
        case 1: return static_cast<char32_t>(0xAC00 + rng.below(0xD7A4 - 0xAC00));  // 한글 음절
        case 2: {
            auto cp = static_cast<char32_t>(0x80 + rng.below(0x10000 - 0x80));
            return (cp >= 0xD800 && cp <= 0xDFFF) ? U'?' : cp;
        }
        default: return static_cast<char32_t>(0x10000 + rng.below(0x110000 - 0x10000));
    }
}

// 깨진 UTF-8 이 자주 나오도록 lead·continuation byte 를 섞는다.
std::string random_bytes(pa_test::SplitMix64& rng) {
    static constexpr unsigned char interesting[] = {0x00, 0x41, 0x7F, 0x80, 0xBF, 0xC0, 0xC1, 0xC2,
                                                    0xDF, 0xE0, 0xED, 0xEF, 0xF0, 0xF4, 0xF5, 0xFF};
    std::string out;
    const auto length = rng.below(24);
    for (std::uint64_t i = 0; i < length; ++i) {
        out.push_back(static_cast<char>(rng.chance(1, 2) ? interesting[rng.below(sizeof(interesting))]
                                                         : rng.below(256)));
    }
    return out;
}

}  // namespace

TEST(CoreUtf8Property, EncodedCodepointsRoundTrip) {
    const auto config = pa_test::property_config();
    for (const auto seed : config.seeds) {
        pa_test::SplitMix64 rng(seed);
        for (std::size_t iteration = 0; iteration < config.iterations; ++iteration) {
            std::vector<char32_t> codepoints(rng.below(16));
            std::string text;
            for (auto& cp : codepoints) {
                cp = random_codepoint(rng);
                append_utf8(text, cp);
            }
            SCOPED_TRACE(testing::Message() << "seed=" << seed << " iteration=" << iteration);
            ASSERT_TRUE(pc::validate_utf8(text));
            const auto units = pc::decode_utf8(text);
            ASSERT_TRUE(units);
            ASSERT_EQ(units->size(), codepoints.size());
            std::size_t expected_begin = 0;
            for (std::size_t i = 0; i < units->size(); ++i) {
                const auto& unit = (*units)[i];
                EXPECT_EQ(unit.value, codepoints[i]);
                EXPECT_EQ(unit.source.begin().value(), expected_begin);
                expected_begin = unit.source.end().value();
                EXPECT_EQ(*pc::to_byte_offset(text, pc::CodepointOffset{i}), unit.source.begin());
                EXPECT_EQ(*pc::to_codepoint_offset(text, unit.source.begin()), pc::CodepointOffset{i});
            }
            EXPECT_EQ(expected_begin, text.size());
        }
    }
}

TEST(CoreUtf8Property, ValidateAgreesWithDecode) {
    const auto config = pa_test::property_config();
    for (const auto seed : config.seeds) {
        pa_test::SplitMix64 rng(seed);
        for (std::size_t iteration = 0; iteration < config.iterations; ++iteration) {
            const auto bytes = random_bytes(rng);
            SCOPED_TRACE(testing::Message() << "seed=" << seed << " iteration=" << iteration);
            const auto valid = pc::validate_utf8(bytes);
            const auto decoded = pc::decode_utf8(bytes);
            ASSERT_EQ(valid.has_value(), decoded.has_value());
            if (decoded) {
                std::string again;
                for (const auto& unit : *decoded) {
                    append_utf8(again, unit.value);
                }
                EXPECT_EQ(again, bytes);
            }
        }
    }
}
