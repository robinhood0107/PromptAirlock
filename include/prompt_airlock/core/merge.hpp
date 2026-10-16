#pragma once

#include <span>
#include <vector>

#include "prompt_airlock/core/entity.hpp"
#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// 겹치는 탐지 결과를 합친 한 덩어리.
// action 은 들어온 종류들 중 가장 엄격한 처리, label_type 은 가명 라벨에 쓸 대표 종류다.
struct MergedEntity {
    SegmentIndex segment;
    ByteSpan span;
    Action action;
    EntityType label_type;
    EntityTypeSet types;
    bool operator==(const MergedEntity&) const noexcept = default;
};

// 같은 segment 에서 구간이 겹치면(맞닿기만 하면 따로) 하나로 합친다.
// 결과는 (segment, 시작) 순으로 정렬되고 서로 겹치지 않으며, 입력 순서와 무관하다.
// 대표 종류는 이긴 처리 방식을 가진 종류 중 고정 우선순위로 고른다:
// 차단 종류는 enum 순, 가명화 종류는 Email, IpAddress, KoreanPhone, KoreanBusinessNo, InternalTerm,
// Organization, Person 순(형식 있는 값 > 기관 보호어 > 이름·조직).
[[nodiscard]] std::vector<MergedEntity> merge_entities(std::span<const EntitySpan> spans);

}  // namespace prompt_airlock::core
