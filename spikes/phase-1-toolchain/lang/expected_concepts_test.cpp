// std::expected 오류 전파, concepts 계약, ranges 변환을 확인한다.
#include <gtest/gtest.h>

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <expected>
#include <ranges>
#include <span>
#include <string_view>
#include <vector>

namespace {

enum class EntityType { Person, Organization, Email };

struct EntitySpan {
    std::size_t start;
    std::size_t end;
    EntityType type;
};

enum class DetectError { InputTooLarge, Overloaded };

// detector 계약: 입력 view 를 받아 span 목록 또는 오류를 돌려준다.
template <class D>
concept Detector = requires(const D& d, std::string_view text) {
    { d.detect(text) } -> std::same_as<std::expected<std::vector<EntitySpan>, DetectError>>;
};

struct FixedDetector {
    std::size_t max_bytes;
    std::expected<std::vector<EntitySpan>, DetectError> detect(std::string_view text) const {
        if (text.size() > max_bytes) {
            return std::unexpected(DetectError::InputTooLarge);
        }
        return std::vector<EntitySpan>{{0, 9, EntityType::Person}, {10, 22, EntityType::Organization}};
    }
};

struct NotADetector {
    int detect(std::string_view) const { return 0; }
};

static_assert(Detector<FixedDetector>);
static_assert(!Detector<NotADetector>);

enum class Decision { Pass, Tokenize, Block };

// 오류는 숨기지 않고 BLOCK 으로 닫힌다.
template <Detector D>
Decision decide(const D& detector, std::string_view text) {
    return detector.detect(text)
        .transform([](const std::vector<EntitySpan>& spans) {
            return spans.empty() ? Decision::Pass : Decision::Tokenize;
        })
        .value_or(Decision::Block);
}

std::vector<EntityType> person_types(std::span<const EntitySpan> spans) {
    // clang-23 + libstdc++-14 조합은 `| std::ranges::to<std::vector>()` 파이프 형태를 컴파일하지 못한다. 함수 호출 형태를 쓴다.
    return std::ranges::to<std::vector>(
        spans | std::views::filter([](const EntitySpan& s) { return s.type == EntityType::Person; }) |
        std::views::transform(&EntitySpan::type));
}

}  // namespace

TEST(Expected, ErrorFailsClosed) {
    const FixedDetector small{.max_bytes = 4};
    const FixedDetector large{.max_bytes = 1024};
    EXPECT_EQ(decide(small, "김민수 과장"), Decision::Block);
    EXPECT_EQ(decide(large, "김민수 과장"), Decision::Tokenize);
}

TEST(Expected, AndThenPropagatesError) {
    const FixedDetector d{.max_bytes = 2};
    const auto count = d.detect("abc").and_then([](const auto& v) -> std::expected<std::size_t, DetectError> {
        return v.size();
    });
    ASSERT_FALSE(count.has_value());
    EXPECT_EQ(count.error(), DetectError::InputTooLarge);
}

TEST(Ranges, FilterTransformTo) {
    const std::vector<EntitySpan> spans{{0, 9, EntityType::Person},
                                        {10, 22, EntityType::Organization},
                                        {30, 39, EntityType::Person}};
    const auto persons = person_types(spans);
    EXPECT_EQ(persons.size(), 2u);
    EXPECT_TRUE(std::ranges::all_of(persons, [](EntityType t) { return t == EntityType::Person; }));
}
