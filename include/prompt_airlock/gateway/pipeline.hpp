// 요청 처리 단계. 인증·등급 확정(server) 뒤에 부른다.
// 순서: JSON 읽기 → 파라미터 → 탐지 → 정책 → 가명 범위 → 가명화 → 잔여 검사 → provider 요청 → provider 호출
// → 응답 읽기 → 응답 검사 → 같은 범위에서 복원 → 새로 만든 응답.
// 어느 단계든 실패하면 거절하고 provider 는 부르지 않는다(fail closed).
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "prompt_airlock/audit/log.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/privacy.hpp"
#include "prompt_airlock/core/request_params.hpp"
#include "prompt_airlock/core/restore.hpp"
#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/gateway/error_body.hpp"
#include "prompt_airlock/gateway/server.hpp"

namespace prompt_airlock::gateway {

// 요청 하나의 가명 범위(운영은 Vault 범위, 시험은 가짜). 요청이 끝나면 함께 사라지고 범위도 지워진다.
class PseudonymScope {
public:
    template <class S>
        requires core::TokenIssuer<S> && core::TokenResolver<S>
    explicit PseudonymScope(S scope) : self_(std::make_unique<Model<S>>(std::move(scope))) {}

    [[nodiscard]] std::expected<core::Token, core::ProtectionError> issue(core::EntityType type, std::string_view value) {
        return self_->issue(type, value);
    }
    [[nodiscard]] std::expected<core::SensitiveText, core::RestoreError> resolve(const core::Token& token) {
        return self_->resolve(token);
    }

private:
    struct Concept {
        virtual ~Concept() = default;
        virtual std::expected<core::Token, core::ProtectionError> issue(core::EntityType, std::string_view) = 0;
        virtual std::expected<core::SensitiveText, core::RestoreError> resolve(const core::Token&) = 0;
    };
    template <class S>
    struct Model final : Concept {
        explicit Model(S s) : scope(std::move(s)) {}
        std::expected<core::Token, core::ProtectionError> issue(core::EntityType type, std::string_view value) override {
            return scope.issue(type, value);
        }
        std::expected<core::SensitiveText, core::RestoreError> resolve(const core::Token& token) override {
            return scope.resolve(token);
        }
        S scope;
    };
    std::unique_ptr<Concept> self_;
};

using ScopeOpener = std::function<std::expected<PseudonymScope, core::VaultError>()>;

struct ProviderReply {
    unsigned status;
    std::string body;
};

enum class ProviderError : std::uint8_t { Unavailable, Timeout, BadResponse };

// provider 호출. 검증된 요청 본문만 받는다. 주소와 자격 증명은 구현(provider 클라이언트)이 가진다.
using ProviderCall =
    std::function<boost::asio::awaitable<std::expected<ProviderReply, ProviderError>>(std::string body)>;

// 잠정값(Phase 9-3 측정으로 확정). NER 대기열 16칸, Vault 연결 8개보다 많이 받아도 안에서 기다릴 뿐이다.
inline constexpr unsigned pipeline_work_threads = 4;
inline constexpr std::size_t pipeline_in_flight_limit = 16;

class Pipeline {
public:
    // detectors 는 Pipeline 보다 오래 살아야 한다. 여러 연결이 함께 부르므로 open_scope·provider 는 스레드 안전해야 한다.
    // work 는 탐지·Vault·감사 쓰기 같은 동기 단계를 돌리는 크기 정해진 작업 풀이다. provider 호출은 handle 을 부른 실행기(io)에서 한다.
    Pipeline(const detect::Detectors& detectors, ScopeOpener open_scope, ProviderCall provider,
             core::OutputTokenCap output_cap, std::string model_alias, boost::asio::any_io_executor work,
             audit::AuditLog* audit = nullptr, std::size_t in_flight_limit = pipeline_in_flight_limit);

    // audit 가 있으면 요청 결과와 외부 전송 이력을 남긴다. 기록하지 못하면 거절한다(ADR 0021).
    // 처리 중 요청이 in_flight_limit 에 닿아 있으면 아무 단계도 거치지 않고 503 overloaded 로 끝낸다.
    [[nodiscard]] boost::asio::awaitable<JsonResponse> handle(AcceptedRequest request) const;

private:
    struct Trace;
    struct Outbound {
        std::optional<PseudonymScope> scope;  // 응답 복원도 같은 범위에서만 한다
        std::string body;                     // provider 로 보낼 검증된 본문
    };
    boost::asio::awaitable<JsonResponse> run(AcceptedRequest request, Trace& trace) const;
    std::expected<Outbound, JsonResponse> prepare(AcceptedRequest request, Trace& trace) const;
    JsonResponse finish(const std::expected<ProviderReply, ProviderError>& reply, PseudonymScope& scope,
                        Trace& trace) const;

    const detect::Detectors& detectors_;
    ScopeOpener open_scope_;
    ProviderCall provider_;
    core::OutputTokenCap output_cap_;
    std::string model_alias_;
    boost::asio::any_io_executor work_;
    audit::AuditLog* audit_;
    std::size_t in_flight_limit_;
    mutable std::atomic<std::size_t> in_flight_{0};
};

}  // namespace prompt_airlock::gateway
