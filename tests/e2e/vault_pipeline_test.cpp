// 실제 탐지기 + core 판정 + 실제 Vault + mock provider 로 요청 하나를 처음부터 끝까지 시험한다. 값은 모두 합성이다.
// 순서: 탐지 → 정책 검사 → Vault 범위 열기 → 보호 → 보호 후 재탐지·잔여 검사 → provider 요청 → 응답 검사 → 복원.
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "prng.hpp"
#include "prompt_airlock/core/grade.hpp"
#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/privacy.hpp"
#include "prompt_airlock/core/provider_boundary.hpp"
#include "prompt_airlock/core/residual.hpp"
#include "prompt_airlock/core/restore.hpp"
#include "prompt_airlock/core/token.hpp"
#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/vault_client/service.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#endif

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pv = prompt_airlock::vault_client;
using namespace std::chrono_literals;
using pc::EntityType;
using pc::MessageRole;

namespace {

void kill_process(std::uint64_t pid) {
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    ASSERT_NE(h, nullptr);
    TerminateProcess(h, 9);
    WaitForSingleObject(h, 5000);
    CloseHandle(h);
#else
    ASSERT_EQ(::kill(static_cast<pid_t>(pid), SIGKILL), 0);
#endif
}

struct Turn {
    MessageRole role;
    std::string text;
};

// 요청 하나의 결과. 범위는 응답 복원까지 살아 있어야 하므로 함께 들고 다닌다.
struct Request {
    std::expected<void, pc::Rejection> result;
    std::optional<pv::VaultScope> scope;
    int provider_calls = 0;
    std::vector<std::string> sent;  // mock provider 가 받은 글(메시지 part 순서)
};

class Gateway {
public:
    explicit Gateway(std::chrono::milliseconds restart_min = 0ms) : service_(options(restart_min)) {}

    // after_open: 범위를 연 직후 부른다(장애 주입용).
    Request send(const std::vector<Turn>& turns, const std::function<void()>& after_open = {}) {
        Request out{{}, std::nullopt, 0, {}};
        const auto fail = [&](pc::Rejection r) {
            out.result = std::unexpected(std::move(r));
            return std::move(out);
        };
        pc::PromptDocumentBuilder builder;
        for (const auto& turn : turns) {
            std::vector<pc::SensitiveText> parts;
            parts.push_back(pc::SensitiveText::copy_of(turn.text));
            builder.add_message(turn.role, pc::ContentForm::String, std::move(parts));
        }
        auto raw = pc::RawPrompt::create(*std::move(builder).build(),
                                         *pc::RequestParams::create({}, pc::OutputTokenCap::standard()),
                                         *pc::resolve_grade(pc::GradePolicy::OOnly, {}));
        const auto detected = detectors_.detect(raw.document());
        if (!detected) {
            return fail(pc::Rejection::from_error(detected.error()));
        }
        auto checked = pc::check_policy(std::move(raw), detected->entities, pc::Policy::standard());
        if (!checked) {
            return fail(checked.error());
        }
        auto scope = service_.open_scope();
        if (!scope) {
            return fail(pc::Rejection::from_error(pc::VaultError::Unavailable));
        }
        out.scope.emplace(std::move(*scope));
        if (after_open) {
            after_open();
        }
        auto protected_prompt = pc::protect(std::move(*checked), *out.scope);
        if (!protected_prompt) {
            return fail(protected_prompt.error());
        }
        const auto residual = detectors_.detect(protected_prompt->document());
        if (!residual) {
            return fail(pc::Rejection::from_error(residual.error()));
        }
        auto verified =
            pc::verify_residual(std::move(*protected_prompt), pc::ResidualReport{residual->entities, residual->encoded});
        if (!verified) {
            return fail(verified.error());
        }
        const auto request = pc::make_provider_request(*verified);
        if (!request) {
            return fail(request.error());
        }
        ++out.provider_calls;
        for (const auto& message : request->messages()) {
            for (const auto& part : message.parts) {
                out.sent.emplace_back(part.view());
            }
        }
        return out;
    }

    // provider 응답을 다시 탐지해 검사하고, 그 요청의 범위에서 복원한다.
    std::expected<pc::SensitiveText, pc::Rejection> restore(Request& request, std::string_view answer) {
        std::vector<pc::SensitiveText> parts;
        parts.push_back(pc::SensitiveText::copy_of(answer));
        pc::PromptDocumentBuilder builder;
        builder.add_message(MessageRole::Model, pc::ContentForm::String, std::move(parts));
        const auto found = detectors_.detect(*std::move(builder).build());
        if (!found) {
            return std::unexpected(pc::Rejection::from_error(found.error()));
        }
        auto checked = pc::check_response(pc::SensitiveText::copy_of(answer), found->entities);
        if (!checked) {
            return std::unexpected(checked.error());
        }
        const auto plan = pc::plan_restore(*checked);
        if (!plan) {
            return std::unexpected(plan.error());
        }
        return pc::apply_restore(std::move(*checked), *plan, *request.scope);
    }

    pv::VaultService& service() { return service_; }

private:
    static pv::ServiceOptions options(std::chrono::milliseconds restart_min) {
        pv::ServiceOptions o;
        o.exe = PA_VAULT_EXE;
        o.restart_min = restart_min;
        o.connection.io_timeout = 3000ms;
        return o;
    }

    pd::Detectors detectors_ = *pd::Detectors::make({});
    pv::VaultService service_;
};

bool contains(const std::vector<std::string>& sent, std::string_view value) {
    return std::ranges::any_of(sent, [&](const std::string& s) { return s.find(value) != std::string::npos; });
}

const std::string phone = "010-2345-6789";
const std::string email = "user1@example.invalid";
const std::string ip = "192.0.2.10";

}  // namespace

TEST(VaultPipelineE2E, RoundTripRestoresOriginalsAndSendsNone) {
    Gateway gateway;
    const std::string text = phone + " 이나 " + email + ", " + ip + " 으로 연락 주세요. 다시 " + phone;
    auto request = gateway.send({{MessageRole::User, text}});
    ASSERT_TRUE(request.result) << pc::reason_code_name(request.result.error().code());
    ASSERT_EQ(request.provider_calls, 1);
    for (const std::string_view original : {std::string_view(phone), std::string_view("2345"), std::string_view(email),
                                            std::string_view(ip)}) {
        EXPECT_FALSE(contains(request.sent, original)) << original;
    }
    const auto tokens = pc::scan_tokens(request.sent[0]);
    ASSERT_EQ(tokens.size(), 4U);
    EXPECT_EQ(tokens[0].token, tokens[3].token);  // 같은 값은 같은 token

    // mock provider 는 받은 질문을 그대로 인용해 답한다.
    const auto restored = gateway.restore(request, "확인했습니다. " + request.sent[0]);
    ASSERT_TRUE(restored) << pc::reason_code_name(restored.error().code());
    EXPECT_EQ(restored->view(), "확인했습니다. " + text);
}

TEST(VaultPipelineE2E, BlockedTypesNeverReachVaultOrProvider) {
    Gateway gateway;
    for (const std::string_view text : {"제 주민번호는 900101-1234567 입니다", "카드 4111-1111-1111-1111 로 결제",
                                        "키 AKIA0000AAAA1111BBBB 를 넣었어요"}) {
        const auto request = gateway.send({{MessageRole::User, std::string(text)}});
        ASSERT_FALSE(request.result) << text;
        EXPECT_EQ(request.result.error().code(), pc::ReasonCode::EntityBlocked);
        EXPECT_EQ(request.provider_calls, 0);
        EXPECT_FALSE(request.scope);
    }
    EXPECT_FALSE(gateway.service().vault_pid());  // 정책에서 거절되어 Vault 를 띄우지도 않았다
}

TEST(VaultPipelineE2E, MultiTurnNeverLeaksEarlierOriginals) {
    Gateway gateway;
    const std::string first = "담당자 연락처는 " + phone + ", 메일은 " + email + " 입니다.";
    auto turn1 = gateway.send({{MessageRole::User, first}});
    ASSERT_TRUE(turn1.result);
    const auto answer1 = gateway.restore(turn1, "정리하면 " + turn1.sent[0]);
    ASSERT_TRUE(answer1);
    ASSERT_NE(answer1->view().find(phone), std::string_view::npos);  // 사용자는 원문 답을 받는다

    // 2턴: 클라이언트가 1턴 질문과 복원된 답을 다시 보낸다. 모든 역할을 다시 탐지하므로 원문이 나가지 않는다.
    auto turn2 = gateway.send({{MessageRole::User, first},
                               {MessageRole::Model, std::string(answer1->view())},
                               {MessageRole::User, "위 연락처로 보낼 안내문을 써 주세요."}});
    ASSERT_TRUE(turn2.result) << pc::reason_code_name(turn2.result.error().code());
    ASSERT_EQ(turn2.sent.size(), 3U);
    for (const std::string_view original : {std::string_view(phone), std::string_view(email)}) {
        EXPECT_FALSE(contains(turn2.sent, original)) << original;
    }
    // 1턴 token 은 1턴 범위에만 있다. 2턴 범위에서는 풀리지 않는다.
    const auto cross = turn2.scope->resolve(pc::scan_tokens(turn1.sent[0])[0].token);
    ASSERT_FALSE(cross);
    EXPECT_EQ(cross.error(), pc::RestoreError::TokenNotFound);
}

TEST(VaultPipelineE2E, RestoredValuesComeOnlyFromTheSameRequest) {
    // 고정 seed 로 값을 섞은 요청을 만들고, 그 범위에서 풀리는 값이 모두 그 요청의 입력 값인지 본다.
    Gateway gateway;
    pa_test::SplitMix64 rng(20261019);
    const std::vector<std::string> pool = {phone,         "010-9876-5432", email, "user2@example.invalid",
                                           ip,            "198.51.100.7",  "02-3456-7890"};
    auto other = gateway.service().open_scope();
    ASSERT_TRUE(other);
    const auto foreign = other->issue(EntityType::Email, "user9@example.invalid");
    ASSERT_TRUE(foreign);

    for (int round = 0; round < 30; ++round) {
        std::string text = "참고:";
        std::set<std::string> used;
        const auto count = 1 + rng.below(4);
        for (std::uint64_t i = 0; i < count; ++i) {
            const auto& value = pool[rng.below(pool.size())];
            used.insert(value);
            text += " " + value + " ,";
        }
        auto request = gateway.send({{MessageRole::User, text}});
        ASSERT_TRUE(request.result) << text;
        for (const auto& found : pc::scan_tokens(request.sent[0])) {
            const auto value = request.scope->resolve(found.token);
            ASSERT_TRUE(value);
            EXPECT_TRUE(used.contains(std::string(value->view()))) << "round " << round;
        }
        // 다른 범위의 token 은 이 범위에서 풀리지 않고, 응답에 섞이면 응답 전체를 거절한다.
        const auto cross = gateway.restore(request, "답: " + std::string(foreign->text()));
        ASSERT_FALSE(cross);
        EXPECT_EQ(cross.error().code(), pc::ReasonCode::ResponseTokenUnresolved);
    }
}

TEST(VaultPipelineE2E, VaultKilledBeforeIssueSendsNothingThenRecovers) {
    Gateway gateway;
    const std::string text = "연락처 " + phone;
    auto failed = gateway.send({{MessageRole::User, text}}, [&] {
        const auto pid = gateway.service().vault_pid();
        ASSERT_TRUE(pid);
        kill_process(*pid);
    });
    ASSERT_FALSE(failed.result);
    EXPECT_EQ(failed.result.error().code(), pc::ReasonCode::ProtectionUnavailable);
    EXPECT_EQ(failed.provider_calls, 0);

    const auto next = gateway.send({{MessageRole::User, text}});
    ASSERT_TRUE(next.result);
    EXPECT_EQ(next.provider_calls, 1);
    EXPECT_FALSE(contains(next.sent, phone));
}

TEST(VaultPipelineE2E, VaultKilledBeforeRestoreRejectsTheResponse) {
    Gateway gateway;
    auto request = gateway.send({{MessageRole::User, "연락처 " + phone}});
    ASSERT_TRUE(request.result);
    const auto pid = gateway.service().vault_pid();
    ASSERT_TRUE(pid);
    kill_process(*pid);
    const auto restored = gateway.restore(request, "확인: " + request.sent[0]);
    ASSERT_FALSE(restored);
    EXPECT_EQ(restored.error().code(), pc::ReasonCode::ProtectionUnavailable);  // 복원기 장애(TokenNotFound 와 구분)
    // token 이 없는 응답은 Vault 없이도 그대로 돌려준다.
    const auto plain = gateway.restore(request, "연락처를 확인했습니다.");
    ASSERT_TRUE(plain);
}
