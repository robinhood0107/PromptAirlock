#pragma once

#include <span>
#include <vector>

#include "prompt_airlock/core/detail/attributes.hpp"
#include "prompt_airlock/core/detail/state_key.hpp"
#include "prompt_airlock/core/document.hpp"
#include "prompt_airlock/core/grade.hpp"
#include "prompt_airlock/core/merge.hpp"
#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/request_params.hpp"
#include "prompt_airlock/core/strategy.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// 질문의 네 단계(spec §5). 원문 → 정책 확인 → 보호 → 검증 완료 순서로만 바뀐다.
// 다음 단계는 정해진 core 함수만 만들고(열쇠), 단계는 복사되지 않고 넘겨지기만 한다.
// 단계 함수는 이전 단계를 값으로 받아, 거절돼도 원문이 호출한 쪽에 남지 않는다.

// 등급이 O 로 확정된 원문 질문.
class RawPrompt {
public:
    [[nodiscard]] static RawPrompt create(PromptDocument document, RequestParams params, OpenGrade grade) noexcept;

    RawPrompt(const RawPrompt&) = delete;
    RawPrompt& operator=(const RawPrompt&) = delete;
    RawPrompt(RawPrompt&&) noexcept = default;
    RawPrompt& operator=(RawPrompt&&) noexcept = default;
    ~RawPrompt() = default;

    [[nodiscard]] const PromptDocument& document() const& noexcept PA_LIFETIMEBOUND { return document_; }
    const PromptDocument& document() const&& = delete;
    [[nodiscard]] const RequestParams& params() const noexcept { return params_; }
    [[nodiscard]] OpenGrade grade() const noexcept { return grade_; }

private:
    RawPrompt(PromptDocument document, RequestParams params, OpenGrade grade) noexcept;

    PromptDocument document_;
    RequestParams params_;
    OpenGrade grade_;
};

// 정책 검사를 통과한 질문. 차단 대상이 없고, 탐지 결과는 합쳐져 있다.
// 검사 때의 가명화 전략을 담아 이후 단계가 정책을 다시 받지 않게 한다(요청 중 정책 불변).
class PolicyCheckedPrompt {
public:
    PolicyCheckedPrompt(detail::StateKey<PolicyCheckedPrompt>, RawPrompt raw, std::vector<MergedEntity> entities,
                        PrivacyStrategy strategy) noexcept;

    PolicyCheckedPrompt(const PolicyCheckedPrompt&) = delete;
    PolicyCheckedPrompt& operator=(const PolicyCheckedPrompt&) = delete;
    PolicyCheckedPrompt(PolicyCheckedPrompt&&) noexcept = default;
    PolicyCheckedPrompt& operator=(PolicyCheckedPrompt&&) noexcept = default;
    ~PolicyCheckedPrompt() = default;

    [[nodiscard]] const PromptDocument& document() const& noexcept PA_LIFETIMEBOUND { return raw_.document(); }
    const PromptDocument& document() const&& = delete;
    [[nodiscard]] const RequestParams& params() const noexcept { return raw_.params(); }
    [[nodiscard]] OpenGrade grade() const noexcept { return raw_.grade(); }
    [[nodiscard]] std::span<const MergedEntity> entities() const& noexcept PA_LIFETIMEBOUND { return entities_; }
    std::span<const MergedEntity> entities() const&& = delete;
    [[nodiscard]] PrivacyStrategy strategy() const noexcept { return strategy_; }

private:
    RawPrompt raw_;
    std::vector<MergedEntity> entities_;
    PrivacyStrategy strategy_;
};

// 보호 단계에서 바꿔 넣은 자리(보호 후 텍스트 기준 위치). 원문 값은 담지 않는다.
struct Replacement {
    SegmentIndex segment;
    ByteSpan span;
    EntityType type;
    bool operator==(const Replacement&) const noexcept = default;
};

// 개인정보를 가명·표지로 바꾼 질문. 원문 묶음은 이 단계를 만들 때 지워진다.
class ProtectedPrompt {
public:
    ProtectedPrompt(detail::StateKey<ProtectedPrompt>, PromptDocument protected_document, RequestParams params,
                    OpenGrade grade, std::vector<Replacement> replacements) noexcept;

    ProtectedPrompt(const ProtectedPrompt&) = delete;
    ProtectedPrompt& operator=(const ProtectedPrompt&) = delete;
    ProtectedPrompt(ProtectedPrompt&&) noexcept = default;
    ProtectedPrompt& operator=(ProtectedPrompt&&) noexcept = default;
    ~ProtectedPrompt() = default;

    [[nodiscard]] const PromptDocument& document() const& noexcept PA_LIFETIMEBOUND { return document_; }
    const PromptDocument& document() const&& = delete;
    [[nodiscard]] const RequestParams& params() const noexcept { return params_; }
    [[nodiscard]] OpenGrade grade() const noexcept { return grade_; }
    [[nodiscard]] std::span<const Replacement> replacements() const& noexcept PA_LIFETIMEBOUND { return replacements_; }
    std::span<const Replacement> replacements() const&& = delete;

private:
    PromptDocument document_;
    RequestParams params_;
    OpenGrade grade_;
    std::vector<Replacement> replacements_;
};

// 잔여 검사까지 통과한 질문. provider 로 보낼 payload 전체(검증된 segment + 범위 검사된 파라미터)다.
class VerifiedPrompt {
public:
    VerifiedPrompt(detail::StateKey<VerifiedPrompt>, ProtectedPrompt prompt) noexcept;

    VerifiedPrompt(const VerifiedPrompt&) = delete;
    VerifiedPrompt& operator=(const VerifiedPrompt&) = delete;
    VerifiedPrompt(VerifiedPrompt&&) noexcept = default;
    VerifiedPrompt& operator=(VerifiedPrompt&&) noexcept = default;
    ~VerifiedPrompt() = default;

    [[nodiscard]] const PromptDocument& document() const& noexcept PA_LIFETIMEBOUND { return prompt_.document(); }
    const PromptDocument& document() const&& = delete;
    [[nodiscard]] const RequestParams& params() const noexcept { return prompt_.params(); }
    [[nodiscard]] OpenGrade grade() const noexcept { return prompt_.grade(); }

private:
    ProtectedPrompt prompt_;
};

}  // namespace prompt_airlock::core
