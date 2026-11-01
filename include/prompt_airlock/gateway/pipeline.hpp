// 요청 처리 단계. 인증·등급 확정(server) 뒤에 부른다.
// 순서: JSON 읽기 → 파라미터 → 탐지 → 정책 → 가명 범위 → 가명화 → 잔여 검사 → provider 요청 → provider 호출
// → 응답 읽기 → 응답 검사 → 같은 범위에서 복원 → 새로 만든 응답.
// 어느 단계든 실패하면 거절하고 provider 는 부르지 않는다(fail closed).
// 시간 상한을 넘기거나 부른 쪽이 취소하면(연결 끊김) 남은 단계를 멈추고 가명 범위를 지운 뒤 거절로 끝낸다.
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>
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
#include "prompt_airlock/gateway/confirm.hpp"
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

// 문장 판별(경고 모드, ADR 0023). text 는 메시지 segment 하나, named_person 은 NER 이 그 segment 에서 사람을 찾았는지다.
// 걸리면 범주 이름, 아니면 nullopt. 판별하지 못하면 탐지 실패로 거절한다(fail closed).
using SentenceCheck = std::function<std::expected<std::optional<std::string>, core::DetectError>(
    std::string_view text, bool named_person, std::stop_token stop)>;

// 측정(#143)으로 확정(#144). NER 대기열 16칸, Vault 연결 8개보다 많이 받아도 안에서 기다릴 뿐이다.
// 동시 32개 과부하에서 16개를 받고 나머지는 바로 거절했고, 받은 요청의 왕복 p95 는 약 4초였다.
inline constexpr unsigned pipeline_work_threads = 4;
inline constexpr std::size_t pipeline_in_flight_limit = 16;
// 요청 하나의 전체 시간 상한(#144). provider 상한 120초 + NER 최악 약 4.1초 3번 + 여유.
inline constexpr std::chrono::seconds request_time_limit{150};

class Pipeline {
public:
    // detectors 는 Pipeline 보다 오래 살아야 한다. 여러 연결이 함께 부르므로 open_scope·provider 는 스레드 안전해야 한다.
    // work 는 탐지·Vault·감사 쓰기 같은 동기 단계를 돌리는 크기 정해진 작업 풀이다. provider 호출은 handle 을 부른 실행기(io)에서 한다.
    Pipeline(const detect::Detectors& detectors, ScopeOpener open_scope, ProviderCall provider,
             core::OutputTokenCap output_cap, std::string model_alias, boost::asio::any_io_executor work,
             audit::AuditLog* audit = nullptr, std::size_t in_flight_limit = pipeline_in_flight_limit,
             std::chrono::milliseconds time_limit = request_time_limit, SentenceCheck sentence = {});

    // audit 가 있으면 요청 결과와 외부 전송 이력을 남긴다. 기록하지 못하면 거절한다(ADR 0021).
    // 처리 중 요청이 in_flight_limit 에 닿아 있으면 아무 단계도 거치지 않고 503 overloaded 로 끝낸다.
    // time_limit 을 넘기면 504 timeout, 부른 쪽이 asio 취소를 보내면 cancelled 로 끝낸다. 취소 신호를 주고받으므로
    // 한 요청은 strand(또는 스레드 하나)에서 불러야 한다.
    // sentence 가 있으면 규칙을 통과한 요청의 메시지를 판별해, 걸리면 409 confirmation_required 와 확인 표지를 돌려준다.
    // 같은 본문에 그 표지를 붙여 다시 보내면 한 번 통과한다(ADR 0023).
    [[nodiscard]] boost::asio::awaitable<JsonResponse> handle(AcceptedRequest request) const;

private:
    struct Trace;
    struct Outbound {
        std::optional<PseudonymScope> scope;  // 응답 복원도 같은 범위에서만 한다
        std::string body;                     // provider 로 보낼 검증된 본문
    };
    boost::asio::awaitable<JsonResponse> run(AcceptedRequest request, Trace& trace) const;
    std::expected<Outbound, JsonResponse> prepare(AcceptedRequest request, Trace& trace, std::stop_token stop) const;
    JsonResponse finish(const std::expected<ProviderReply, ProviderError>& reply, PseudonymScope& scope, Trace& trace,
                        std::stop_token stop) const;

    const detect::Detectors& detectors_;
    ScopeOpener open_scope_;
    ProviderCall provider_;
    core::OutputTokenCap output_cap_;
    std::string model_alias_;
    boost::asio::any_io_executor work_;
    audit::AuditLog* audit_;
    std::size_t in_flight_limit_;
    std::chrono::milliseconds time_limit_;
    SentenceCheck sentence_;        // 비어 있으면 경고 모드를 쓰지 않는다
    mutable ConfirmLedger confirms_;
    mutable std::atomic<std::size_t> in_flight_{0};
};

}  // namespace prompt_airlock::gateway
