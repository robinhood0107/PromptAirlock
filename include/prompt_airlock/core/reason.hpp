#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

#include "prompt_airlock/core/detail/attributes.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// 거절 사유 코드. 값은 감사 기록과 오류 응답에 남으므로 바꾸지 않는다.
enum class ReasonCode : std::uint16_t {
    GradeClassified = 100,
    GradeSensitive = 101,
    GradeUnresolved = 102,
    InvalidText = 200,
    EmptyPrompt = 201,
    PromptTooLarge = 202,
    TooManyEntities = 203,
    FieldNotAllowed = 300,
    ContentPartNotAllowed = 301,
    ParameterOutOfRange = 302,
    StreamNotAllowed = 303,
    EntityBlocked = 400,
    EncodedTarget = 401,
    OpaqueEncodedBlob = 402,
    ResidualFound = 403,
    ResponseTokenInLink = 500,
    ResponseBlockedValue = 501,
    ResponseTokenUnresolved = 502,
    DetectorUnavailable = 900,
    ProtectionUnavailable = 901,
    InternalError = 902,
};

[[nodiscard]] std::string_view reason_code_name(ReasonCode code) noexcept;

// 내부 실패를 사유 코드로 바꾼다. 모든 오류 값이 어떤 거절 코드로든 이어진다(fail closed).
[[nodiscard]] ReasonCode to_reason(const CoreError& error) noexcept;

// 사용자에게 돌려줄 정보. 위치·건수·detector 종류를 담을 자리가 없다(우회 탐색 방지).
// blocked_types 는 EntityBlocked 일 때만 채운다(사용자가 그 부분을 지우고 다시 보내게, ADR 0016).
struct UserRejection {
    ReasonCode code;
    EntityTypeSet blocked_types;
    bool operator==(const UserRejection&) const noexcept = default;
};

// 감사 기록에만 남기는 위치. 원문 값은 담지 않는다.
struct EntityFinding {
    SegmentIndex segment;
    ByteSpan span;
    EntityType type;
    DetectorKind detector;
    bool operator==(const EntityFinding&) const noexcept = default;
};
struct ResponseLocation {
    ByteSpan span;
    bool operator==(const ResponseLocation&) const noexcept = default;
};
using AuditFinding = std::variant<EntityFinding, ResponseLocation>;

struct AuditRejection {
    ReasonCode code;
    EntityTypeSet blocked_types;
    std::vector<AuditFinding> findings;
    std::optional<CoreError> cause;
};

// 판정 함수가 돌려주는 거절. 사용자용과 감사용을 나눠 꺼낸다.
class Rejection {
public:
    [[nodiscard]] static Rejection of(ReasonCode code) noexcept;
    [[nodiscard]] static Rejection from_error(CoreError error) noexcept;
    [[nodiscard]] static Rejection with_findings(ReasonCode code, EntityTypeSet types,
                                                 std::vector<AuditFinding> findings) noexcept;

    [[nodiscard]] ReasonCode code() const noexcept { return detail_.code; }
    [[nodiscard]] UserRejection for_user() const noexcept;
    [[nodiscard]] const AuditRejection& for_audit() const& noexcept PA_LIFETIMEBOUND { return detail_; }
    const AuditRejection& for_audit() const&& = delete;

private:
    explicit Rejection(AuditRejection detail) noexcept;

    AuditRejection detail_;
};

}  // namespace prompt_airlock::core
