// 처리 단계 시험: 가짜 가명 범위와 가짜 provider 로, 거절 경로마다 provider 호출이 0 인지와
// provider 로 나가는 본문에 원문이 없는지를 본다.
#include "prompt_airlock/gateway/pipeline.hpp"

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <vector>

#include "../../src/gateway/role_name.hpp"
#include "fake_vault.hpp"
#include "mock_provider.hpp"

namespace {

namespace asio = boost::asio;
namespace core = prompt_airlock::core;
namespace detect = prompt_airlock::detect;
namespace gw = prompt_airlock::gateway;
using json = nlohmann::json;

// 살아 있는 가명 범위 수. 범위 하나에 하나 만들고 범위가 사라질 때 함께 사라진다.
struct LiveScope {
    explicit LiveScope(std::atomic<int>& count) : count_(count) { ++count_; }
    LiveScope(const LiveScope&) = delete;
    LiveScope& operator=(const LiveScope&) = delete;
    ~LiveScope() { --count_; }

private:
    std::atomic<int>& count_;
};

// 가짜 범위가 실패하도록 고를 수 있게 감싼다.
class TestScope {
public:
    TestScope(std::shared_ptr<pa_test::FakeVault> vault, bool fail_issue, std::atomic<int>& live)
        : vault_(std::move(vault)), fail_(fail_issue), live_(std::make_shared<LiveScope>(live)) {}
    std::expected<core::Token, core::ProtectionError> issue(core::EntityType type, std::string_view value) {
        if (fail_) {
            return std::unexpected(core::ProtectionError::IssuerUnavailable);
        }
        return vault_->issue(type, value);
    }
    std::expected<core::SensitiveText, core::RestoreError> resolve(const core::Token& token) {
        return vault_->resolve(token);
    }

private:
    std::shared_ptr<pa_test::FakeVault> vault_;
    bool fail_;
    std::shared_ptr<LiveScope> live_;
};

class FailingNer final : public detect::NerScanner {
public:
    std::expected<std::vector<core::EntitySpan>, core::DetectError> scan(std::string_view, core::SegmentIndex,
                                                                        const detect::DetectionView&, std::stop_token) const override {
        return std::unexpected(core::DetectError::Unavailable);
    }
};

// 취소 신호가 올 때까지(최대 5초) 기다린다. 신호를 받으면 NerPool 처럼 Timeout 을 낸다.
class StopNer final : public detect::NerScanner {
public:
    std::expected<std::vector<core::EntitySpan>, core::DetectError> scan(std::string_view, core::SegmentIndex,
                                                                        const detect::DetectionView&,
                                                                        std::stop_token stop) const override {
        std::unique_lock lock(mutex_);
        (void)changed_.wait_for(lock, stop, std::chrono::seconds(5), [] { return false; });
        if (stop.stop_requested()) {
            stopped_ = true;
            return std::unexpected(core::DetectError::Timeout);
        }
        return std::vector<core::EntitySpan>{};
    }
    bool stopped() const { return stopped_; }

private:
    mutable std::mutex mutex_;
    mutable std::condition_variable_any changed_;
    mutable std::atomic<bool> stopped_{false};
};

// 문이 열릴 때까지(최대 5초) 기다렸다가 아무것도 찾지 않는다. 기다리다 시간이 다 됐는지를 남긴다.
class GatedNer final : public detect::NerScanner {
public:
    std::expected<std::vector<core::EntitySpan>, core::DetectError> scan(std::string_view, core::SegmentIndex,
                                                                        const detect::DetectionView&, std::stop_token) const override {
        ++calls_;
        if (gate_.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
            timed_out_ = true;
        }
        return std::vector<core::EntitySpan>{};
    }
    void open() { opener_.set_value(); }
    int calls() const { return calls_; }
    bool timed_out() const { return timed_out_; }

private:
    std::promise<void> opener_;
    std::shared_future<void> gate_ = opener_.get_future().share();
    mutable std::atomic<int> calls_{0};
    mutable std::atomic<bool> timed_out_{false};
};

class GatewayPipeline : public ::testing::Test {
protected:
    gw::Pipeline make(const detect::Detectors& detectors, std::size_t in_flight_limit = gw::pipeline_in_flight_limit,
                      std::chrono::milliseconds time_limit = gw::request_time_limit, gw::SentenceCheck sentence = {}) {
        return gw::Pipeline(
            detectors,
            [this]() -> std::expected<gw::PseudonymScope, core::VaultError> {
                if (vault_down_) {
                    return std::unexpected(core::VaultError::Unavailable);
                }
                return gw::PseudonymScope(TestScope(vault_, issuer_fails_, live_scopes_));
            },
            [this](std::string body) -> asio::awaitable<std::expected<gw::ProviderReply, gw::ProviderError>> {
                ++provider_calls_;
                sent_.push_back(std::move(body));
                if (during_first_provider_call_ && provider_calls_ == 1) {
                    co_await during_first_provider_call_();
                }
                if (provider_hangs_) {
                    // 답하지 않는 provider. 취소되면 바로 돌아온다(실제 클라이언트가 연결을 끊는 것과 같다).
                    asio::steady_timer never(co_await asio::this_coro::executor, std::chrono::hours(1));
                    (void)co_await never.async_wait(asio::as_tuple(asio::use_awaitable));
                    co_return std::unexpected(gw::ProviderError::Unavailable);
                }
                if (provider_fails_) {
                    co_return std::unexpected(gw::ProviderError::Timeout);
                }
                co_return gw::ProviderReply{200, answer_ ? answer_(sent_.back()) : pa_mock::make_answer(sent_.back())};
            },
            *core::OutputTokenCap::make(512), "demo-alias", work_.get_executor(), nullptr, in_flight_limit, time_limit,
            std::move(sentence));
    }

    gw::JsonResponse run(const gw::Pipeline& pipeline, std::string body,
                         core::GradePolicy policy = core::GradePolicy::OOnly, std::string confirm = {}) {
        asio::io_context io;
        auto grade = core::resolve_grade(policy, {});
        auto future = asio::co_spawn(
            io, pipeline.handle(gw::AcceptedRequest{nullptr, *grade, std::move(body), {}, std::move(confirm)}),
            asio::use_future);
        io.run();
        return future.get();
    }

    static std::string ask(std::string_view text) {
        return json{{"model", "client-model"}, {"messages", json::array({{{"role", "user"}, {"content", text}}})}}.dump();
    }

    static std::string code_of(const gw::JsonResponse& r) { return json::parse(r.body)["error"]["code"]; }

    // provider 가 내는 답(content 만 정한다)
    static std::string answer_with(std::string_view content, json message_extra = json::object()) {
        json message = {{"role", gw::detail::role_name(core::MessageRole::Model)}, {"content", content}};
        message.update(message_extra);
        return json{{"choices", json::array({{{"index", 0}, {"message", message}, {"finish_reason", "stop"}}})}}.dump();
    }

    // 보낸 본문에서 첫 token 을 꺼낸다
    static std::string first_token(const std::string& sent) {
        const auto open = sent.find(core::token_open);
        const auto close = sent.find(core::token_close, open);
        return sent.substr(open, close + core::token_close.size() - open);
    }

    std::function<std::string(const std::string&)> answer_;
    std::function<asio::awaitable<void>()> during_first_provider_call_;  // 첫 요청이 provider 를 기다리는 동안 할 일

    asio::thread_pool work_{2};

    detect::Detectors detectors_ = *detect::Detectors::make({});
    std::shared_ptr<pa_test::FakeVault> vault_ = std::make_shared<pa_test::FakeVault>(20261022);
    bool vault_down_ = false;
    bool issuer_fails_ = false;
    bool provider_fails_ = false;
    bool provider_hangs_ = false;
    std::atomic<int> live_scopes_{0};
    int provider_calls_ = 0;
    std::vector<std::string> sent_;
};

TEST_F(GatewayPipeline, SendsOnlyPseudonymizedRequestBuiltByGateway) {
    const auto pipeline = make(detectors_);
    const auto reply = run(pipeline, ask("담당자 연락처 010-2345-6789, 메일 kim.demo@example.org 로 회신 부탁"));
    ASSERT_EQ(provider_calls_, 1);
    const json sent = json::parse(sent_.front());
    // 원문은 나가지 않는다
    EXPECT_EQ(sent_.front().find("010-2345-6789"), std::string::npos);
    EXPECT_EQ(sent_.front().find("kim.demo@example.org"), std::string::npos);
    const std::string content = sent["messages"][0]["content"];
    EXPECT_NE(content.find(std::string(core::token_open)), std::string::npos);
    // 게이트웨이가 정한 값만 들어간다
    EXPECT_EQ(sent["model"], "demo-alias");
    EXPECT_EQ(sent["max_tokens"], 512);
    EXPECT_EQ(sent["n"], 1);
    EXPECT_EQ(sent["stream"], false);
    EXPECT_FALSE(sent.contains("store"));
    // 답은 같은 범위에서 원래 값으로 되돌아온다
    ASSERT_EQ(reply.status, 200u) << reply.body;
    const json answer = json::parse(reply.body);
    const std::string restored = answer["choices"][0]["message"]["content"];
    EXPECT_NE(restored.find("010-2345-6789"), std::string::npos);
    EXPECT_NE(restored.find("kim.demo@example.org"), std::string::npos);
    EXPECT_EQ(restored.find(std::string(core::token_open)), std::string::npos);
    EXPECT_EQ(answer["model"], "demo-alias");
    EXPECT_TRUE(answer["id"].get<std::string>().starts_with("chatcmpl-pa-"));
}

TEST_F(GatewayPipeline, KeepsContentPartsAndStop) {
    const auto pipeline = make(detectors_);
    const std::string body =
        R"({"messages":[{"role":"user","content":[{"type":"text","text":"첫째"},{"type":"text","text":"둘째"}]}],)"
        R"("stop":"끝","max_tokens":100000,"temperature":0.2})";
    (void)run(pipeline, body);
    ASSERT_EQ(provider_calls_, 1);
    const json sent = json::parse(sent_.front());
    ASSERT_TRUE(sent["messages"][0]["content"].is_array());
    EXPECT_EQ(sent["messages"][0]["content"][1]["text"], "둘째");
    EXPECT_EQ(sent["stop"][0], "끝");
    EXPECT_EQ(sent["max_tokens"], 512);  // 상한으로 줄인다
    EXPECT_EQ(sent["temperature"], 0.2);
}

TEST_F(GatewayPipeline, EveryRejectionMakesZeroProviderCalls) {
    const auto pipeline = make(detectors_);
    struct Case {
        std::string body;
        core::ReasonCode code;
    };
    const std::vector<Case> cases = {
        {"{", core::ReasonCode::InvalidText},
        {R"({"messages":[{"role":"user","content":"a"}],"stream":true})", core::ReasonCode::StreamNotAllowed},
        {R"({"messages":[{"role":"user","content":"a"}],"n":2})", core::ReasonCode::ParameterOutOfRange},
        {ask("제 주민번호는 900101-1234567 입니다"), core::ReasonCode::EntityBlocked},
        // 합성 주민번호를 base64 로 감싼 것
        {ask("확인 부탁: OTAwMTAxLTEyMzQ1Njc="), core::ReasonCode::EncodedTarget},
    };
    for (const auto& c : cases) {
        const auto reply = run(pipeline, c.body);
        EXPECT_EQ(code_of(reply), core::reason_code_name(c.code)) << c.body;
    }
    EXPECT_EQ(provider_calls_, 0);
}

TEST_F(GatewayPipeline, BlockedTypesAreReportedWithoutValues) {
    const auto pipeline = make(detectors_);
    const auto reply = run(pipeline, ask("제 주민번호는 900101-1234567 입니다"));
    EXPECT_EQ(reply.status, 400u);
    EXPECT_EQ(reply.body.find("900101"), std::string::npos);
    EXPECT_EQ(json::parse(reply.body)["error"]["blocked_types"][0].get<std::string>(), core::entity_type_name(core::EntityType::KoreanRrn));
}

TEST_F(GatewayPipeline, InfrastructureFailuresFailClosed) {
    const auto pipeline = make(detectors_);
    vault_down_ = true;
    EXPECT_EQ(run(pipeline, ask("연락처 010-2345-6789")).status, 503u);
    vault_down_ = false;
    issuer_fails_ = true;
    EXPECT_EQ(run(pipeline, ask("연락처 010-2345-6789")).status, 503u);
    issuer_fails_ = false;
    const auto broken = detect::Detectors::make({}, std::make_shared<FailingNer>());
    ASSERT_TRUE(broken.has_value());
    const auto ner_down = make(*broken);
    EXPECT_EQ(code_of(run(ner_down, ask("회의 안건 정리"))), core::reason_code_name(core::ReasonCode::DetectorUnavailable));
    EXPECT_EQ(provider_calls_, 0);
}

// 가짜 판별기: "정신과" 가 든 메시지를 Health 로 본다. 불린 횟수와 받은 사람 여부를 남긴다.
gw::SentenceCheck fake_sentence(std::atomic<int>& calls, bool fail = false) {
    return [&calls, fail](std::string_view text, bool, std::stop_token)
               -> std::expected<std::optional<std::string>, core::DetectError> {
        ++calls;
        if (fail) {
            return std::unexpected(core::DetectError::Unavailable);
        }
        return text.find("정신과") != std::string_view::npos ? std::optional<std::string>("Health") : std::nullopt;
    };
}

TEST_F(GatewayPipeline, WarnModeAsksOnceThenSendsWithTheToken) {
    std::atomic<int> calls{0};
    const auto pipeline = make(detectors_, gw::pipeline_in_flight_limit, gw::request_time_limit, fake_sentence(calls));
    const auto body = ask("동료가 요즘 정신과 다닌대요. 일정 조정 부탁드립니다.");
    const auto first = run(pipeline, body);
    EXPECT_EQ(first.status, 409u);
    EXPECT_EQ(code_of(first), "confirmation_required");
    EXPECT_EQ(first.body.find("정신과"), std::string::npos);  // 문장은 되돌려 주지 않는다
    const auto error = json::parse(first.body)["error"];
    EXPECT_EQ(error["categories"], json::array({"Health"}));
    const auto token = error["confirm_token"].get<std::string>();
    EXPECT_EQ(token.size(), gw::confirm_token_chars);
    EXPECT_EQ(provider_calls_, 0);
    EXPECT_EQ(live_scopes_, 0);

    EXPECT_EQ(run(pipeline, body, core::GradePolicy::OOnly, token).status, 200u);
    EXPECT_EQ(provider_calls_, 1);
    // 한 번 쓴 표지는 다시 쓸 수 없다
    EXPECT_EQ(run(pipeline, body, core::GradePolicy::OOnly, token).status, 409u);
    EXPECT_EQ(provider_calls_, 1);
    // 걸리지 않는 요청은 표지 없이 그대로 간다
    EXPECT_EQ(run(pipeline, ask("회의 안건 정리")).status, 200u);
    EXPECT_EQ(provider_calls_, 2);
}

TEST_F(GatewayPipeline, WarnTokenIsBoundToTheBody) {
    std::atomic<int> calls{0};
    const auto pipeline = make(detectors_, gw::pipeline_in_flight_limit, gw::request_time_limit, fake_sentence(calls));
    const auto token =
        json::parse(run(pipeline, ask("김 과장이 정신과 진료를 받는다고 합니다.")).body)["error"]["confirm_token"].get<std::string>();
    EXPECT_EQ(run(pipeline, ask("이 대리가 정신과 진료를 받는다고 합니다."), core::GradePolicy::OOnly, token).status, 409u);
    EXPECT_EQ(run(pipeline, ask("김 과장이 정신과 진료를 받는다고 합니다."), core::GradePolicy::OOnly, "0123").status, 409u);
    EXPECT_EQ(provider_calls_, 0);
}

TEST_F(GatewayPipeline, WarnModeFailsClosedAndSkipsRuleBlockedRequests) {
    std::atomic<int> calls{0};
    const auto failing = make(detectors_, gw::pipeline_in_flight_limit, gw::request_time_limit, fake_sentence(calls, true));
    EXPECT_EQ(code_of(run(failing, ask("회의 안건 정리"))), core::reason_code_name(core::ReasonCode::DetectorUnavailable));
    EXPECT_EQ(calls, 1);
    // 규칙이 막은 요청은 판별기까지 가지 않는다
    EXPECT_EQ(code_of(run(failing, ask("제 주민번호는 900101-1234567 입니다"))),
              core::reason_code_name(core::ReasonCode::EntityBlocked));
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(provider_calls_, 0);
}

TEST_F(GatewayPipeline, ProviderFailureReturnsFixedError) {
    provider_fails_ = true;
    const auto pipeline = make(detectors_);
    const auto reply = run(pipeline, ask("회의 안건 정리"));
    EXPECT_EQ(reply.status, 502u);
    EXPECT_EQ(code_of(reply), "provider_error");
}

TEST_F(GatewayPipeline, RejectsOverLimitRightAwayWithoutProvider) {
    const auto pipeline = make(detectors_, 1);
    gw::JsonResponse second{};
    during_first_provider_call_ = [&]() -> asio::awaitable<void> {
        second = co_await pipeline.handle(
            gw::AcceptedRequest{nullptr, *core::resolve_grade(core::GradePolicy::OOnly, {}), ask("연락처 010-2345-6789")});
    };
    const auto first = run(pipeline, ask("연락처 010-2345-6789"));
    EXPECT_EQ(first.status, 200u) << first.body;
    EXPECT_EQ(second.status, 503u);
    EXPECT_EQ(code_of(second), "overloaded");
    EXPECT_EQ(provider_calls_, 1);
    // 끝난 요청은 자리를 돌려주므로 다음 요청은 다시 받는다
    EXPECT_EQ(run(pipeline, ask("회의 안건 정리")).status, 200u);
    EXPECT_EQ(provider_calls_, 2);
}

TEST_F(GatewayPipeline, DetectionDoesNotHoldTheIoThread) {
    const auto ner = std::make_shared<GatedNer>();
    const auto gated = detect::Detectors::make({}, ner);
    ASSERT_TRUE(gated.has_value());
    const auto pipeline = make(*gated);
    asio::io_context io;  // io 스레드 하나
    auto reply = asio::co_spawn(
        io, pipeline.handle(gw::AcceptedRequest{nullptr, *core::resolve_grade(core::GradePolicy::OOnly, {}), ask("회의 안건 정리")}),
        asio::use_future);
    // 요청이 탐지에서 기다리는 동안에도 같은 io 스레드에 올린 일이 돌아 문을 연다. 탐지가 io 스레드를 막으면 5초를 다 기다린다.
    asio::post(io, [&] { ner->open(); });
    io.run();
    EXPECT_EQ(reply.get().status, 200u);
    EXPECT_GT(ner->calls(), 0);
    EXPECT_FALSE(ner->timed_out());
}

TEST_F(GatewayPipeline, TimeLimitCutsAHangingProviderAndDropsTheScope) {
    provider_hangs_ = true;
    const auto pipeline = make(detectors_, gw::pipeline_in_flight_limit, std::chrono::milliseconds(200));
    const auto start = std::chrono::steady_clock::now();
    const auto reply = run(pipeline, ask("연락처 010-2345-6789"));
    EXPECT_EQ(reply.status, 504u);
    EXPECT_EQ(code_of(reply), "timeout");
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));  // provider 를 기다리지 않는다
    EXPECT_EQ(provider_calls_, 1);
    EXPECT_EQ(live_scopes_.load(), 0);  // 응답 전에 범위를 지웠다
}

TEST_F(GatewayPipeline, TimeLimitStopsWaitingDetectionWithoutProvider) {
    const auto ner = std::make_shared<StopNer>();
    const auto stuck = detect::Detectors::make({}, ner);
    ASSERT_TRUE(stuck.has_value());
    const auto pipeline = make(*stuck, gw::pipeline_in_flight_limit, std::chrono::milliseconds(200));
    const auto start = std::chrono::steady_clock::now();
    const auto reply = run(pipeline, ask("회의 안건 정리"));
    EXPECT_EQ(reply.status, 504u);
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(3));  // NER 의 5초를 다 기다리지 않는다
    EXPECT_TRUE(ner->stopped());
    EXPECT_EQ(provider_calls_, 0);
    EXPECT_EQ(live_scopes_.load(), 0);
}

TEST_F(GatewayPipeline, CallerCancelDuringProviderEndsAsCancelled) {
    provider_hangs_ = true;
    const auto pipeline = make(detectors_);
    asio::io_context io;
    asio::cancellation_signal client_gone;
    during_first_provider_call_ = [&]() -> asio::awaitable<void> {
        // 연결 끊김: 서버가 처리 중인 요청에 asio 취소를 보낸다
        asio::post(io, [&] { client_gone.emit(asio::cancellation_type::terminal); });
        co_return;
    };
    auto reply = asio::co_spawn(
        io, pipeline.handle(gw::AcceptedRequest{nullptr, *core::resolve_grade(core::GradePolicy::OOnly, {}), ask("연락처 010-2345-6789")}),
        asio::bind_cancellation_slot(client_gone.slot(), asio::use_future));
    io.run();
    const auto cancelled = reply.get();
    EXPECT_EQ(code_of(cancelled), "cancelled");
    EXPECT_EQ(provider_calls_, 1);
    EXPECT_EQ(live_scopes_.load(), 0);
}

TEST_F(GatewayPipeline, ResponseChecksRejectUnsafeAnswers) {
    const auto pipeline = make(detectors_);
    const auto code = [&](std::function<std::string(const std::string&)> answer) {
        answer_ = std::move(answer);
        return code_of(run(pipeline, ask("연락처 010-2345-6789 로 안내")));
    };
    // 링크 주소 안의 token
    EXPECT_EQ(code([](const std::string& sent) { return answer_with("[자료](https://example.org/?q=" + first_token(sent) + ")"); }),
              core::reason_code_name(core::ReasonCode::ResponseTokenInLink));
    // 모델이 바꾼 token: 되돌리지 않고 응답 전체를 거절한다
    EXPECT_EQ(code([](const std::string& sent) {
                  std::string token = first_token(sent);
                  const auto last = token.size() - core::token_close.size() - 1;
                  token[last] = token[last] == 'A' ? 'B' : 'A';  // 같은 문자 집합 안에서 한 글자만 바꾼다
                  return answer_with("연락처는 " + token + " 입니다");
              }),
              core::reason_code_name(core::ReasonCode::ResponseTokenUnresolved));
    // 차단 종류 값이 답에 새로 나타남
    EXPECT_EQ(code([](const std::string&) { return answer_with("예시 번호 900101-1234567"); }),
              core::reason_code_name(core::ReasonCode::ResponseBlockedValue));
    // 스크립트가 담긴 답(대소문자 섞어도)
    EXPECT_EQ(code([](const std::string&) { return answer_with("<ScRiPt>alert(1)</script>"); }),
              core::reason_code_name(core::ReasonCode::ResponseActiveContent));
    EXPECT_EQ(code([](const std::string&) { return answer_with("[x](JavaScript:alert(1))"); }),
              core::reason_code_name(core::ReasonCode::ResponseActiveContent));
    // 도구 호출이 담긴 답
    EXPECT_EQ(code([](const std::string&) { return answer_with("x", {{"tool_calls", json::array({{{"id", "c"}}})}}); }),
              "provider_error");
}

}  // namespace
