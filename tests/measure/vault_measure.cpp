// Vault 발급·복원 지연 측정(Phase 6 계획, 결정 #75 기준). 기본 빌드·ctest 에 넣지 않고 직접 실행한다.
//   cmake --build <빌드 디렉터리> --target vault_measure && <빌드 디렉터리>/tests/measure/vault_measure
// 실제 Vault 프로세스를 띄워 범위 열기·닫기, token 발급, 복원, token N개 응답 복원, 합성 연락처 문서의 보호 전체 시간과
// token 수, 연결 풀 대기 초과 동작을 잰다. 원문은 출력하지 않는다. token 64개 복원 p95 가 10 ms 를 넘으면 종료 코드 1.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "prng.hpp"
#include "prompt_airlock/core/grade.hpp"
#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/privacy.hpp"
#include "prompt_airlock/core/residual.hpp"
#include "prompt_airlock/core/restore.hpp"
#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/vault_client/service.hpp"

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pv = prompt_airlock::vault_client;
using namespace std::chrono_literals;
using pc::EntityType;

namespace {

constexpr std::uint64_t seed = 20261019;
constexpr double batch_limit_ms = 10.0;  // token 64개 복원 p95 기준(결정 #75)

double percentile(std::vector<double> v, double p) {
    std::ranges::sort(v);
    return v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))];
}

double time_ms(const std::function<void()>& fn) {
    const auto start = std::chrono::steady_clock::now();
    fn();
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
}

void row(const char* name, const std::vector<double>& ms) {
    std::printf("%-40s p50 %8.3f  p95 %8.3f  max %8.3f  (n=%zu)\n", name, percentile(ms, 0.5), percentile(ms, 0.95),
                *std::ranges::max_element(ms), ms.size());
}

pv::ServiceOptions options() {
    pv::ServiceOptions o;
    o.exe = PA_VAULT_EXE;
    return o;
}

std::string email(std::size_t i) { return "user" + std::to_string(i) + "@example.invalid"; }

// 서로 다른 값 n 개의 token 으로 만든 응답을 복원하는 시간(범위·발급은 시간에서 뺀다).
std::vector<double> restore_timings(pv::VaultService& service, std::size_t n, std::size_t runs, bool& ok) {
    std::vector<double> out;
    for (std::size_t r = 0; r < runs; ++r) {
        auto scope = service.open_scope();
        if (!scope) {
            ok = false;
            return out;
        }
        std::string answer;
        for (std::size_t i = 0; i < n; ++i) {
            const auto token = scope->issue(EntityType::Email, email(i));
            if (!token) {
                ok = false;
                return out;
            }
            answer += std::string(token->text()) + " ";
        }
        auto checked = pc::check_response(pc::SensitiveText::copy_of(answer), {});
        if (!checked) {
            ok = false;
            return out;
        }
        const auto plan = pc::plan_restore(*checked);
        if (!plan || plan->occurrences.size() != n) {
            ok = false;
            return out;
        }
        bool restored = false;
        out.push_back(time_ms([&] { restored = pc::apply_restore(std::move(*checked), *plan, *scope).has_value(); }));
        ok &= restored;
    }
    return out;
}

// 업무 문장 사이에 연락처(전화·이메일)를 섞은 합성 문서. 값마다 약 150 byte 라 64 KiB 도 탐지 상한(512) 안이다.
std::string contact_document(pa_test::SplitMix64& rng, std::size_t bytes) {
    std::string out;
    std::size_t i = 0;
    while (out.size() < bytes) {
        out += "회의 자료와 일정표를 정리해서 다음 주 월요일까지 공유해 주세요. 담당 ";
        if (i % 2 == 0) {
            out += "010-" + std::to_string(2000 + rng.below(8000)) + "-" + std::to_string(1000 + rng.below(9000));
        } else {
            out += email(i);
        }
        out += " 입니다.\n";
        ++i;
    }
    out.resize(out.rfind('\n', bytes));
    return out;
}

struct Protected {
    bool ok = false;
    std::size_t tokens = 0;
};

// 탐지 → 정책 검사 → 범위 열기 → 보호 → 재탐지·잔여 검사(provider 요청 직전까지).
Protected protect_document(const pd::Detectors& detectors, pv::VaultService& service, std::string_view text) {
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts));
    auto raw = pc::RawPrompt::create(*std::move(builder).build(),
                                     *pc::RequestParams::create({}, pc::OutputTokenCap::standard()),
                                     *pc::resolve_grade(pc::GradePolicy::OOnly, {}));
    const auto detected = detectors.detect(raw.document());
    if (!detected) {
        return {};
    }
    auto checked = pc::check_policy(std::move(raw), detected->entities, pc::Policy::standard());
    auto scope = service.open_scope();
    if (!checked || !scope) {
        return {};
    }
    auto protected_prompt = pc::protect(std::move(*checked), *scope);
    if (!protected_prompt) {
        return {};
    }
    const auto tokens = protected_prompt->replacements().size();
    const auto residual = detectors.detect(protected_prompt->document());
    if (!residual) {
        return {};
    }
    const auto verified =
        pc::verify_residual(std::move(*protected_prompt), pc::ResidualReport{residual->entities, residual->encoded});
    return {verified.has_value(), tokens};
}

}  // namespace

int main() {
    pv::VaultService service(options());
    pa_test::SplitMix64 rng(seed);
    bool ok = true;

    // 첫 범위가 Vault 를 띄운다. 띄우는 시간은 따로 본다.
    std::printf("vault spawn + first scope (ms)            %8.3f\n", time_ms([&] { ok &= service.open_scope().has_value(); }));

    std::vector<double> scope_ms, issue_ms, resolve_ms;
    for (int r = 0; r < 2000; ++r) {
        scope_ms.push_back(time_ms([&] { ok &= service.open_scope().has_value(); }));  // 열고 소멸 때 DropScope
    }
    {
        auto scope = service.open_scope();
        ok &= scope.has_value();
        std::vector<pc::Token> tokens;
        for (std::size_t i = 0; i < 2000 && scope; ++i) {
            issue_ms.push_back(time_ms([&] {
                auto t = scope->issue(EntityType::Email, email(i));
                ok &= t.has_value();
                if (t) {
                    tokens.push_back(std::move(*t));
                }
            }));
        }
        for (const auto& t : tokens) {
            resolve_ms.push_back(time_ms([&] { ok &= scope->resolve(t).has_value(); }));
        }
    }
    row("open + drop scope (ms)", scope_ms);
    row("issue one token (ms)", issue_ms);
    row("resolve one token (ms)", resolve_ms);

    std::vector<double> restore64;
    for (const std::size_t n : {1U, 8U, 64U, 512U}) {
        const auto ms = restore_timings(service, n, n == 512 ? 50 : 200, ok);
        const auto name = "restore response with " + std::to_string(n) + " tokens (ms)";
        row(name.c_str(), ms);
        if (n == 64) {
            restore64 = ms;
        }
    }

    // 합성 연락처 문서의 보호 전체 시간(provider 요청 직전까지)과 요청당 token 수.
    const auto detectors = *pd::Detectors::make({});
    for (const std::size_t bytes : {4U * 1024U, 64U * 1024U}) {
        std::vector<double> ms;
        std::size_t tokens = 0;
        for (int r = 0; r < (bytes > 4096 ? 30 : 200); ++r) {
            const auto text = contact_document(rng, bytes);
            Protected p;
            ms.push_back(time_ms([&] { p = protect_document(detectors, service, text); }));
            ok &= p.ok;
            tokens = std::max(tokens, p.tokens);
        }
        const auto name = "protect " + std::to_string(bytes / 1024) + " KiB, " + std::to_string(tokens) + " tokens (ms)";
        row(name.c_str(), ms);
    }

    // 연결 풀 대기 초과: 연결 1개, 대기 0 ms 에 스레드 16개. 실패는 IssuerUnavailable(fail closed)이고 값이 섞이지 않는다.
    {
        auto o = options();
        o.pool_size = 1;
        o.lease_timeout = 0ms;
        pv::VaultService small(o);
        std::atomic<int> success{0}, exhausted{0}, other_failure{0}, wrong{0};
        std::vector<std::thread> workers;
        for (int t = 0; t < 16; ++t) {
            workers.emplace_back([&, t] {
                for (int i = 0; i < 100; ++i) {
                    auto scope = small.open_scope();
                    if (!scope) {
                        (scope.error().code == pv::ErrorCode::PoolExhausted ? exhausted : other_failure)++;
                        continue;
                    }
                    const auto value = email(static_cast<std::size_t>(t * 1000 + i));
                    const auto token = scope->issue(EntityType::Email, value);
                    if (!token) {
                        (scope->last_error() == pv::ErrorCode::PoolExhausted ? exhausted : other_failure)++;
                        continue;
                    }
                    const auto back = scope->resolve(*token);
                    if (!back) {
                        (scope->last_error() == pv::ErrorCode::PoolExhausted ? exhausted : other_failure)++;
                    } else if (back->view() != value) {
                        ++wrong;
                    } else {
                        ++success;
                    }
                }
            });
        }
        for (auto& w : workers) {
            w.join();
        }
        std::printf("pool 1 / wait 0 ms / 16 threads x 100: success %d, pool exhausted %d, other failure %d, wrong %d\n",
                    success.load(), exhausted.load(), other_failure.load(), wrong.load());
        ok &= wrong.load() == 0 && other_failure.load() == 0;
    }

    const auto p95 = percentile(restore64, 0.95);
    const bool fast = p95 <= batch_limit_ms;
    std::printf("%-40s %8.3f  <= %6.3f  %s\n", "restore 64 tokens p95 (ms)", p95, batch_limit_ms, fast ? "PASS" : "FAIL");
    if (!ok) {
        std::puts("some vault operations failed during measurement");
    }
    return ok && fast ? 0 : 1;
}
