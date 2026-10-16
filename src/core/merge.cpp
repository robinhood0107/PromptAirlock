#include "prompt_airlock/core/merge.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>

namespace prompt_airlock::core {
namespace {

// 대표 종류 우선순위. 작을수록 먼저 고른다. 처리 방식이 같은 종류끼리만 비교한다.
[[nodiscard]] constexpr std::uint8_t label_rank(EntityType type) noexcept {
    switch (type) {
        case EntityType::Email: return 0;
        case EntityType::IpAddress: return 1;
        case EntityType::KoreanPhone: return 2;
        case EntityType::KoreanBusinessNo: return 3;
        case EntityType::InternalTerm: return 4;
        case EntityType::Organization: return 5;
        case EntityType::Person: return 6;
        // 차단 종류는 enum 순서를 그대로 쓴다.
        case EntityType::KoreanRrn:
        case EntityType::ApiKey:
        case EntityType::PrivateKey:
        case EntityType::CardNumber:
        case EntityType::BankAccount:
        case EntityType::Credential:
        case EntityType::SensitivePersonalInfo:
        case EntityType::KoreanPassportNo:
        case EntityType::KoreanDriverLicenseNo:
        case EntityType::KoreanAlienRegistrationNo:
            return static_cast<std::uint8_t>(16 + std::to_underlying(type));
    }
    return std::numeric_limits<std::uint8_t>::max();
}

struct Group {
    SegmentIndex segment;
    ByteSpan span;
    Action action;
    EntityTypeSet types;
};

[[nodiscard]] EntityType pick_label(const Group& group) noexcept {
    EntityType best = EntityType::Person;
    std::uint8_t best_rank = std::numeric_limits<std::uint8_t>::max();
    group.types.for_each([&](EntityType type) {
        if (default_action(type) == group.action && label_rank(type) < best_rank) {
            best = type;
            best_rank = label_rank(type);
        }
    });
    return best;
}

}  // namespace

std::vector<MergedEntity> merge_entities(std::span<const EntitySpan> spans) {
    std::vector<EntitySpan> sorted(spans.begin(), spans.end());
    std::sort(sorted.begin(), sorted.end());

    std::vector<MergedEntity> out;
    out.reserve(sorted.size());
    auto flush = [&out](const Group& group) {
        out.push_back(MergedEntity{group.segment, group.span, group.action, pick_label(group), group.types});
    };

    std::optional<Group> current;
    for (const auto& entity : sorted) {
        // 정렬돼 있으므로 다음 결과는 현재 덩어리와 겹치거나, 그 뒤에서 새로 시작한다.
        const bool joins = current && entity.segment() == current->segment && entity.span().overlaps(current->span);
        if (!joins) {
            if (current) {
                flush(*current);
            }
            current.emplace(Group{entity.segment(), entity.span(), Action::Pass, {}});
        }
        current->span = ByteSpan::hull(current->span, entity.span());
        current->action = stricter(current->action, default_action(entity.type()));
        current->types.insert(entity.type());
    }
    if (current) {
        flush(*current);
    }
    return out;
}

}  // namespace prompt_airlock::core
