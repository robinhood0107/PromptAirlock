#include "prompt_airlock/gateway/pipeline.hpp"

#include "prompt_airlock/core/provider_boundary.hpp"
#include "prompt_airlock/core/residual.hpp"
#include "prompt_airlock/core/restore.hpp"
#include "prompt_airlock/gateway/provider_json.hpp"
#include "prompt_airlock/gateway/request_json.hpp"
#include "prompt_airlock/gateway/response_json.hpp"

#include <chrono>
#include <random>
#include <string_view>

namespace prompt_airlock::gateway {
namespace {

JsonResponse reject(const core::Rejection& rejection) { return error_response(rejection.for_user()); }

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

Pipeline::Pipeline(const detect::Detectors& detectors, ScopeOpener open_scope, ProviderCall provider,
                   core::OutputTokenCap output_cap, std::string model_alias)
    : detectors_(detectors),
      open_scope_(std::move(open_scope)),
      provider_(std::move(provider)),
      output_cap_(output_cap),
      model_alias_(std::move(model_alias)) {}

// shortcut: 탐지·Vault 호출은 동기라 이 coroutine 을 돌리는 io 스레드를 잠시 막는다. 동시 처리 수는 io 스레드 수로 묶인다.
// 요청 단위 시간 상한과 취소는 Phase 9 에서 붙인다.
boost::asio::awaitable<JsonResponse> Pipeline::handle(AcceptedRequest request) const {
    auto parsed = parse_request(request.body);
    if (!parsed) {
        co_return reject(parsed.error());
    }
    auto params = core::RequestParams::create(parsed->params, output_cap_);
    if (!params) {
        co_return reject(params.error());
    }
    auto raw = core::RawPrompt::create(std::move(parsed->document), *params, request.grade);
    const auto detected = detectors_.detect(raw.document());
    if (!detected) {
        co_return reject(core::Rejection::from_error(detected.error()));
    }
    auto checked = core::check_policy(std::move(raw), detected->entities, core::Policy::standard(output_cap_));
    if (!checked) {
        co_return reject(checked.error());
    }
    // 가명 범위는 이 요청이 끝날 때까지 산다(응답 복원도 같은 범위에서만 한다)
    auto scope = open_scope_();
    if (!scope) {
        co_return reject(core::Rejection::from_error(scope.error()));
    }
    auto protected_prompt = core::protect(std::move(*checked), *scope);
    if (!protected_prompt) {
        co_return reject(protected_prompt.error());
    }
    const auto residual = detectors_.detect(protected_prompt->document());
    if (!residual) {
        co_return reject(core::Rejection::from_error(residual.error()));
    }
    auto verified =
        core::verify_residual(std::move(*protected_prompt), core::ResidualReport{residual->entities, residual->encoded});
    if (!verified) {
        co_return reject(verified.error());
    }
    const auto provider_request = core::make_provider_request(*verified);
    if (!provider_request) {
        co_return reject(provider_request.error());
    }
    const auto reply = co_await provider_(provider_request_body(*provider_request, model_alias_));
    if (!reply || reply->status != 200) {
        co_return error_response(EntryError::ProviderFailed);  // provider 오류 본문은 넘기지 않는다
    }
    auto answer = parse_provider_answer(reply->body);
    if (!answer) {
        co_return error_response(EntryError::ProviderFailed);
    }
    // 응답 검사(ADR 0017 7~9): 다시 탐지 → 차단 값·링크 속 token 이면 거절 → 같은 범위의 token 만 복원
    std::string restored;
    if (!answer->content.empty()) {
        const auto found = detectors_.detect_segment(answer->content.view(), core::SegmentIndex{0});
        if (!found) {
            co_return reject(core::Rejection::from_error(found.error()));
        }
        auto checked = core::check_response(std::move(answer->content), *found);
        if (!checked) {
            co_return reject(checked.error());
        }
        const auto plan = core::plan_restore(*checked);
        if (!plan) {
            co_return reject(plan.error());
        }
        auto text = core::apply_restore(std::move(*checked), *plan, *scope);
        if (!text) {
            co_return reject(text.error());
        }
        restored = std::string(text->view());
    }
    const auto created = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    co_return JsonResponse{200, client_response_body(new_request_id(), created, model_alias_, restored,
                                                     answer->finish_reason, answer->usage)};
}

}  // namespace prompt_airlock::gateway
