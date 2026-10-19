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

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pv = prompt_airlock::vault_client;
using namespace std::chrono_literals;
using pc::EntityType;
using pc::MessageRole;

namespace {

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
