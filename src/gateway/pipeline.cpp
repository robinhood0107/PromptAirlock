#include "prompt_airlock/gateway/pipeline.hpp"

#include "prompt_airlock/core/provider_boundary.hpp"
#include "prompt_airlock/core/residual.hpp"
#include "prompt_airlock/core/restore.hpp"
#include "prompt_airlock/gateway/provider_json.hpp"
#include "prompt_airlock/gateway/request_json.hpp"
#include "prompt_airlock/gateway/response_json.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <type_traits>
#include <chrono>
#include <random>
#include <string_view>

namespace prompt_airlock::gateway {
namespace {

namespace asio = boost::asio;

// 동기 작업 f 를 작업 풀에서 돌리고, 끝나면 이 coroutine 의 실행기로 돌아온다(asio coroutine 은 자기 실행기에서 이어진다).
template <class F>
asio::awaitable<std::invoke_result_t<F&>> on_pool(const asio::any_io_executor& pool, F f) {
    co_return co_await asio::co_spawn(
        pool, [&f]() -> asio::awaitable<std::invoke_result_t<F&>> { co_return f(); }, asio::use_awaitable);
}

// 응답 능동 콘텐츠(ADR 0021): 기관 앱이 그대로 그리면 실행될 수 있는 표지. 대소문자를 가리지 않는다.
bool has_active_content(std::string_view text) {
    std::string lower(text);
    std::ranges::transform(lower, lower.begin(), [](char c) { return c >= 0x41 && c <= 0x5a ? static_cast<char>(c + 32) : c; });
    return lower.find("<script") != std::string::npos || lower.find("javascript:") != std::string::npos ||
           lower.find("vbscript:") != std::string::npos;
}

// 게이트웨이 요청 ID. provider 의 id 대신 클라이언트에 준다.
std::string new_request_id() {
    std::random_device device;
    std::string id = "chatcmpl-pa-";
    constexpr std::string_view hex = "0123456789abcdef";
    for (int i = 0; i < 24; ++i) {
        id.push_back(hex[device() % 16]);
    }
    return id;
}

}  // namespace

// 요청 하나의 감사용 정보. 원문 값은 담지 않는다(사유 코드, 종류 이름, 건수만).
struct Pipeline::Trace {
    std::string id = new_request_id();
    std::string reason;
    nlohmann::json blocked = nlohmann::json::array();
    nlohmann::json entities = nlohmann::json::object();

    JsonResponse reject(const core::Rejection& rejection) {
        const auto user = rejection.for_user();
        reason = core::reason_code_name(user.code);
        user.blocked_types.for_each([&](core::EntityType type) { blocked.push_back(core::entity_type_name(type)); });
        return error_response(user);
    }
    JsonResponse fail(EntryError error) {
        auto response = error_response(error);
        reason = nlohmann::json::parse(response.body)["error"]["code"].get<std::string>();
        return response;
    }
};

Pipeline::Pipeline(const detect::Detectors& detectors, ScopeOpener open_scope, ProviderCall provider,
                   core::OutputTokenCap output_cap, std::string model_alias, asio::any_io_executor work,
                   audit::AuditLog* audit, std::size_t in_flight_limit)
    : detectors_(detectors),
      open_scope_(std::move(open_scope)),
      provider_(std::move(provider)),
      output_cap_(output_cap),
      model_alias_(std::move(model_alias)),
      work_(std::move(work)),
      audit_(audit),
      in_flight_limit_(in_flight_limit) {}

asio::awaitable<JsonResponse> Pipeline::handle(AcceptedRequest request) const {
    const auto start = std::chrono::steady_clock::now();
    Trace trace;
    const std::string origin = request.origin != nullptr ? request.origin->name : std::string();
    const std::string client = request.client;
    struct Slot {
        std::atomic<std::size_t>& count;
        ~Slot() { --count; }
    } slot{in_flight_};
    JsonResponse reply;
    if (in_flight_.fetch_add(1) >= in_flight_limit_) {
        reply = trace.fail(EntryError::Overloaded);  // 기다리게 하지 않는다. 탐지·Vault·provider 모두 0
    } else {
        reply = co_await run(std::move(request), trace);
    }
    if (audit_ != nullptr) {
        const auto ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        nlohmann::json fields = {{"request_id", trace.id}, {"origin", origin},       {"client", client},
                                 {"grade", "O"},           {"status", reply.status}, {"entities", trace.entities},
                                 {"ms", ms},               {"result", reply.status == 200 ? "pass" : "reject"}};
        if (!trace.reason.empty()) {
            fields["reason"] = trace.reason;
            fields["blocked_types"] = trace.blocked;
        }
        if (!audit_->append("request", reply.status == 200 ? "info" : "warn", std::move(fields))) {
            co_return error_response(EntryError::Unavailable);  // 기록하지 못한 요청은 내보내지 않는다
        }
    }
    co_return reply;
}

// 동기 단계는 작업 풀에서, provider 호출만 io 실행기에서 한다. 가명 범위를 닫는 Vault 호출도 작업 풀에서 한다.
// 요청 단위 시간 상한과 취소는 Phase 9-2 에서 붙인다.
asio::awaitable<JsonResponse> Pipeline::run(AcceptedRequest request, Trace& trace) const {
    auto outbound = co_await on_pool(work_, [&] { return prepare(std::move(request), trace); });
    if (!outbound) {
        co_return std::move(outbound.error());
    }
    const auto reply = co_await provider_(std::move(outbound->body));
    co_return co_await on_pool(work_, [&] {
        auto response = finish(reply, *outbound->scope, trace);
        outbound->scope.reset();
        return response;
    });
}

// JSON 읽기부터 외부 전송 이력까지. 거절이면 그 응답을 돌려준다.
std::expected<Pipeline::Outbound, JsonResponse> Pipeline::prepare(AcceptedRequest request, Trace& trace) const {
    auto parsed = parse_request(request.body);
    if (!parsed) {
        return std::unexpected(trace.reject(parsed.error()));
    }
    auto params = core::RequestParams::create(parsed->params, output_cap_);
    if (!params) {
        return std::unexpected(trace.reject(params.error()));
    }
    auto raw = core::RawPrompt::create(std::move(parsed->document), *params, request.grade);
    const auto detected = detectors_.detect(raw.document());
    if (!detected) {
        return std::unexpected(trace.reject(core::Rejection::from_error(detected.error())));
    }
    for (const auto& entity : detected->entities) {
        auto& count = trace.entities[std::string(core::entity_type_name(entity.type()))];
        count = count.is_number() ? count.get<int>() + 1 : 1;
    }
    auto checked = core::check_policy(std::move(raw), detected->entities, core::Policy::standard(output_cap_));
    if (!checked) {
        return std::unexpected(trace.reject(checked.error()));
    }
    auto scope = open_scope_();
    if (!scope) {
        return std::unexpected(trace.reject(core::Rejection::from_error(scope.error())));
    }
    auto protected_prompt = core::protect(std::move(*checked), *scope);
    if (!protected_prompt) {
        return std::unexpected(trace.reject(protected_prompt.error()));
    }
    const auto residual = detectors_.detect(protected_prompt->document());
    if (!residual) {
        return std::unexpected(trace.reject(core::Rejection::from_error(residual.error())));
    }
    auto verified =
        core::verify_residual(std::move(*protected_prompt), core::ResidualReport{residual->entities, residual->encoded});
    if (!verified) {
        return std::unexpected(trace.reject(verified.error()));
    }
    const auto provider_request = core::make_provider_request(*verified);
    if (!provider_request) {
        return std::unexpected(trace.reject(provider_request.error()));
    }
    Outbound outbound{std::move(*scope), provider_request_body(*provider_request, model_alias_)};
    // 외부 전송 이력: 실제로 보내는 가명 상태 본문(ADR 0021). 남기지 못하면 보내지 않는다.
    if (audit_ != nullptr && !audit_->append("egress", "info",
                                             {{"request_id", trace.id}, {"sent", nlohmann::json::parse(outbound.body)}})) {
        return std::unexpected(trace.fail(EntryError::Unavailable));
    }
    return outbound;
}

// provider 답 검사부터 복원한 응답까지.
JsonResponse Pipeline::finish(const std::expected<ProviderReply, ProviderError>& reply, PseudonymScope& scope,
                              Trace& trace) const {
    if (!reply || reply->status != 200) {
        return trace.fail(EntryError::ProviderFailed);  // provider 오류 본문은 넘기지 않는다
    }
    // 복원 전 응답. provider 오류 본문은 남기지 않는다(200 일 때만)
    if (audit_ != nullptr &&
        !audit_->append("egress_answer", "info", {{"request_id", trace.id}, {"answer", reply->body}})) {
        return trace.fail(EntryError::Unavailable);
    }
    auto answer = parse_provider_answer(reply->body);
    if (!answer) {
        return trace.fail(EntryError::ProviderFailed);
    }
    // 응답 검사(ADR 0017 7~9): 다시 탐지 → 차단 값·링크 속 token 이면 거절 → 같은 범위의 token 만 복원
    if (has_active_content(answer->content.view())) {
        return trace.reject(core::Rejection::of(core::ReasonCode::ResponseActiveContent));
    }
    std::string restored;
    if (!answer->content.empty()) {
        const auto found = detectors_.detect_segment(answer->content.view(), core::SegmentIndex{0});
        if (!found) {
            return trace.reject(core::Rejection::from_error(found.error()));
        }
        auto checked = core::check_response(std::move(answer->content), *found);
        if (!checked) {
            return trace.reject(checked.error());
        }
        const auto plan = core::plan_restore(*checked);
        if (!plan) {
            return trace.reject(plan.error());
        }
        auto text = core::apply_restore(std::move(*checked), *plan, scope);
        if (!text) {
            return trace.reject(text.error());
        }
        restored = std::string(text->view());
    }
    const auto created = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    return JsonResponse{200, client_response_body(trace.id, created, model_alias_, restored, answer->finish_reason,
                                                  answer->usage)};
}

}  // namespace prompt_airlock::gateway
