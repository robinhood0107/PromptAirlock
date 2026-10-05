#include "prompt_airlock/core/types.hpp"

#include <gtest/gtest.h>

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace pc = prompt_airlock::core;
using pc::Action;
using pc::EntityType;

namespace {

// ADR 0015·0016 의 표를 시험 쪽에 따로 적는다. 헤더의 switch 를 그대로 베끼지 않는다.
const std::vector<std::pair<EntityType, Action>>& expected_table() {
    static const std::vector<std::pair<EntityType, Action>> table = {
        {EntityType::Person, Action::Tokenize},
        {EntityType::Organization, Action::Tokenize},
        {EntityType::KoreanPhone, Action::Tokenize},
        {EntityType::KoreanRrn, Action::Block},
        {EntityType::KoreanBusinessNo, Action::Tokenize},
        {EntityType::Email, Action::Tokenize},
        {EntityType::ApiKey, Action::Block},
        {EntityType::PrivateKey, Action::Block},
        {EntityType::IpAddress, Action::Tokenize},
        {EntityType::InternalTerm, Action::Tokenize},
        {EntityType::CardNumber, Action::Block},
        {EntityType::BankAccount, Action::Block},
        {EntityType::Credential, Action::Block},
        {EntityType::SensitivePersonalInfo, Action::Block},
        {EntityType::KoreanPassportNo, Action::Block},
        {EntityType::KoreanDriverLicenseNo, Action::Block},
        {EntityType::KoreanAlienRegistrationNo, Action::Block},
    };
    return table;
}

}  // namespace

TEST(CoreTypes, DefaultActionTableMatchesDecision) {
    ASSERT_EQ(expected_table().size(), pc::entity_type_count);
    int blocked = 0;
    int tokenized = 0;
    for (const auto& [type, action] : expected_table()) {
        EXPECT_EQ(pc::default_action(type), action) << pc::entity_type_name(type);
        blocked += action == Action::Block ? 1 : 0;
        tokenized += action == Action::Tokenize ? 1 : 0;
    }
    EXPECT_EQ(blocked, 10);
    EXPECT_EQ(tokenized, 7);
}

TEST(CoreTypes, OutOfRangeTypeIsBlocked) {
    EXPECT_EQ(pc::default_action(static_cast<EntityType>(200)), Action::Block);
    EXPECT_EQ(pc::entity_type_name(static_cast<EntityType>(200)), "INVALID");
}

TEST(CoreTypes, StricterOrdersBlockTokenizePass) {
    EXPECT_EQ(pc::stricter(Action::Pass, Action::Tokenize), Action::Tokenize);
    EXPECT_EQ(pc::stricter(Action::Block, Action::Tokenize), Action::Block);
    EXPECT_EQ(pc::stricter(Action::Tokenize, Action::Block), Action::Block);
    EXPECT_EQ(pc::stricter(Action::Pass, Action::Pass), Action::Pass);
}

TEST(CoreTypes, AllEntityTypesInDeclarationOrder) {
    const auto all = pc::all_entity_types();
    for (std::size_t i = 0; i < all.size(); ++i) {
        EXPECT_EQ(std::to_underlying(all[i]), i);
    }
}

TEST(CoreTypes, NamesAreUniqueUpperSnake) {
    std::set<std::string> seen;
    for (const auto type : pc::all_entity_types()) {
        const auto name = pc::entity_type_name(type);
        ASSERT_FALSE(name.empty());
        EXPECT_TRUE(name.front() >= 'A' && name.front() <= 'Z');
        for (const char c : name) {
            EXPECT_TRUE((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') << name;
        }
        EXPECT_TRUE(seen.insert(std::string(name)).second) << name;
    }
}

TEST(CoreTypes, EntityTypeSetIteratesInEnumOrder) {
    pc::EntityTypeSet set;
    EXPECT_TRUE(set.empty());
    set.insert(EntityType::KoreanAlienRegistrationNo);
    set.insert(EntityType::Person);
    set.insert(EntityType::Person);
    EXPECT_EQ(set.size(), 2U);
    EXPECT_TRUE(set.contains(EntityType::Person));
    EXPECT_FALSE(set.contains(EntityType::Email));

    std::vector<EntityType> order;
    set.for_each([&](EntityType t) { order.push_back(t); });
    EXPECT_EQ(order, (std::vector<EntityType>{EntityType::Person, EntityType::KoreanAlienRegistrationNo}));

    pc::EntityTypeSet other;
    other.insert(EntityType::Email);
    set.merge(other);
    EXPECT_EQ(set.size(), 3U);
}

TEST(CoreTypes, FixedLimits) {
    EXPECT_EQ(pc::max_prompt_bytes, 65536U);
    EXPECT_EQ(pc::max_entities, 512U);
}
