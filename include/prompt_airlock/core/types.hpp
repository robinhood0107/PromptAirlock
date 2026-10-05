#pragma once

#include <array>
#include <bit>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

namespace prompt_airlock::core {

// 기관 분류 등급(ADR 0013). Gateway 는 등급을 판정하거나 낮추지 않는다.
enum class DataGrade : std::uint8_t { Classified, Sensitive, Open };

// 출처마다 등록하는 등급 정책. OOnly: 표시가 없으면 O. Declare: 요청마다 표시가 있어야 한다.
enum class GradePolicy : std::uint8_t { OOnly, Declare };

// 확정된 등급이 어디서 왔는가(감사 기록용).
enum class GradeOrigin : std::uint8_t { Header, SourceDefault };

// 처리 방식. 값이 클수록 엄격하다.
enum class Action : std::uint8_t { Pass = 0, Tokenize = 1, Block = 2 };

// 개인정보·비밀 종류 17개(ADR 0015, 0016).
enum class EntityType : std::uint8_t {
    Person,
    Organization,
    KoreanPhone,
    KoreanRrn,
    KoreanBusinessNo,
    Email,
    ApiKey,
    PrivateKey,
    IpAddress,
    InternalTerm,
    CardNumber,
    BankAccount,
    Credential,
    SensitivePersonalInfo,
    KoreanPassportNo,
    KoreanDriverLicenseNo,
    KoreanAlienRegistrationNo,
};
inline constexpr std::size_t entity_type_count = 17;

// 메시지 역할. 외부 형식의 역할 문자열과는 JSON 경계(Phase 8)에서만 연결한다.
enum class MessageRole : std::uint8_t { System, Developer, User, Model };

// 탐지 결과를 낸 detector 의 종류(감사 기록용).
enum class DetectorKind : std::uint8_t { Pattern, Checksum, Secret, InternalTerm, Context, Ner };

// 고정 한도(ADR 0015). 설정으로 바꿀 수 없다.
// 모든 segment(메시지와 stop 문자열)의 UTF-8 byte 합. 이 값 이하만 받는다.
inline constexpr std::size_t max_prompt_bytes = 64 * 1024;
// 병합하기 전 요청당 탐지 결과 수. 이 값 이하만 받는다.
inline constexpr std::size_t max_entities = 512;

// 종류별 고정 처리 표. 범위 밖 값은 가장 엄격하게 본다.
[[nodiscard]] constexpr Action default_action(EntityType type) noexcept {
    switch (type) {
        case EntityType::ApiKey:
        case EntityType::PrivateKey:
        case EntityType::KoreanRrn:
        case EntityType::CardNumber:
        case EntityType::BankAccount:
        case EntityType::Credential:
        case EntityType::SensitivePersonalInfo:
        case EntityType::KoreanPassportNo:
        case EntityType::KoreanDriverLicenseNo:
        case EntityType::KoreanAlienRegistrationNo:
            return Action::Block;
        case EntityType::Person:
        case EntityType::Organization:
        case EntityType::KoreanPhone:
        case EntityType::KoreanBusinessNo:
        case EntityType::Email:
        case EntityType::IpAddress:
        case EntityType::InternalTerm:
            return Action::Tokenize;
    }
    return Action::Block;
}

[[nodiscard]] constexpr Action stricter(Action a, Action b) noexcept {
    return std::to_underlying(a) < std::to_underlying(b) ? b : a;
}

[[nodiscard]] constexpr std::array<EntityType, entity_type_count> all_entity_types() noexcept {
    std::array<EntityType, entity_type_count> out{};
    for (std::size_t i = 0; i < entity_type_count; ++i) {
        out[i] = static_cast<EntityType>(i);
    }
    return out;
}

// 감사 기록과 사유 표시에 쓰는 이름. 원문 값은 담지 않는다.
[[nodiscard]] constexpr std::string_view entity_type_name(EntityType type) noexcept {
    switch (type) {
        case EntityType::Person: return "PERSON";
        case EntityType::Organization: return "ORGANIZATION";
        case EntityType::KoreanPhone: return "KOREAN_PHONE";
        case EntityType::KoreanRrn: return "KOREAN_RRN";
        case EntityType::KoreanBusinessNo: return "KOREAN_BUSINESS_NO";
        case EntityType::Email: return "EMAIL";
        case EntityType::ApiKey: return "API_KEY";
        case EntityType::PrivateKey: return "PRIVATE_KEY";
        case EntityType::IpAddress: return "IP_ADDRESS";
        case EntityType::InternalTerm: return "INTERNAL_TERM";
        case EntityType::CardNumber: return "CARD_NUMBER";
        case EntityType::BankAccount: return "BANK_ACCOUNT";
        case EntityType::Credential: return "CREDENTIAL";
        case EntityType::SensitivePersonalInfo: return "SENSITIVE_PERSONAL_INFO";
        case EntityType::KoreanPassportNo: return "KOREAN_PASSPORT_NO";
        case EntityType::KoreanDriverLicenseNo: return "KOREAN_DRIVER_LICENSE_NO";
        case EntityType::KoreanAlienRegistrationNo: return "KOREAN_ALIEN_REGISTRATION_NO";
    }
    return "INVALID";
}

// 종류 집합. 순회는 enum 선언 순서로 하므로 입력 순서와 무관하다.
class EntityTypeSet {
public:
    constexpr void insert(EntityType type) noexcept { bits_ |= bit(type); }
    constexpr void merge(EntityTypeSet other) noexcept { bits_ |= other.bits_; }
    [[nodiscard]] constexpr bool contains(EntityType type) const noexcept { return (bits_ & bit(type)) != 0; }
    [[nodiscard]] constexpr bool empty() const noexcept { return bits_ == 0; }
    [[nodiscard]] constexpr std::size_t size() const noexcept {
        return static_cast<std::size_t>(std::popcount(bits_));
    }

    template <class F>
    constexpr void for_each(F&& visit) const {
        for (const auto type : all_entity_types()) {
            if (contains(type)) {
                visit(type);
            }
        }
    }

    constexpr bool operator==(const EntityTypeSet&) const noexcept = default;

private:
    [[nodiscard]] static constexpr std::uint32_t bit(EntityType type) noexcept {
        return std::uint32_t{1} << std::to_underlying(type);
    }

    std::uint32_t bits_ = 0;
};

// 검사 대상 묶음 안의 segment 순번.
class SegmentIndex {
public:
    constexpr explicit SegmentIndex(std::uint32_t value) noexcept : value_(value) {}
    [[nodiscard]] constexpr std::uint32_t value() const noexcept { return value_; }
    constexpr auto operator<=>(const SegmentIndex&) const noexcept = default;

private:
    std::uint32_t value_;
};

}  // namespace prompt_airlock::core
