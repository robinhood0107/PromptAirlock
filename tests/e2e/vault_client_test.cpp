// 실제 Vault 프로세스로 C++ 클라이언트를 검증한다. 값은 모두 합성이다.
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "prompt_airlock/core/token.hpp"
#include "prompt_airlock/vault_client/connection.hpp"
#include "prompt_airlock/vault_client/process.hpp"
#include "prompt_airlock/vault_client/service.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#endif

namespace pc = prompt_airlock::core;
namespace pv = prompt_airlock::vault_client;
using namespace std::chrono_literals;
using pc::EntityType;

namespace {

pv::ServiceOptions options(std::chrono::milliseconds restart_min = 0ms) {
    pv::ServiceOptions o;
    o.exe = PA_VAULT_EXE;
    o.restart_min = restart_min;
    o.connection.io_timeout = 3000ms;
    return o;
}

// 운영체제 수준에서 Vault 를 강제 종료한다(장애 흉내).
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

}  // namespace

TEST(VaultClientE2E, IssueAndResolveExactly) {
    pv::VaultService service(options());
    auto scope = service.open_scope();
    ASSERT_TRUE(scope) << pv::to_string(scope.error().code);

    const auto a = scope->issue(EntityType::Email, "user1@example.invalid");
    ASSERT_TRUE(a);
    EXPECT_TRUE(a->text().starts_with("⟦EMAIL_"));
    const auto same = scope->issue(EntityType::Email, "user1@example.invalid");
    ASSERT_TRUE(same);
    EXPECT_EQ(*a, *same);  // 같은 범위·종류·값은 같은 token
    const auto other = scope->issue(EntityType::Email, "user2@example.invalid");
    ASSERT_TRUE(other);
    EXPECT_NE(*a, *other);

    const auto back = scope->resolve(*a);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->view(), "user1@example.invalid");
}

TEST(VaultClientE2E, ScopesAreIsolated) {
    pv::VaultService service(options());
    auto first = service.open_scope();
    auto second = service.open_scope();
    ASSERT_TRUE(first && second);
    const auto token = first->issue(EntityType::Person, "가상인");
    ASSERT_TRUE(token);
    const auto other = second->resolve(*token);
    ASSERT_FALSE(other);
    EXPECT_EQ(other.error(), pc::RestoreError::TokenNotFound);
    EXPECT_EQ(second->last_error(), pv::ErrorCode::TokenNotFound);
}

TEST(VaultClientE2E, BlockTypesAreNeverSentToVault) {
    pv::VaultService service(options());
    auto scope = service.open_scope();
    ASSERT_TRUE(scope);
    const auto r = scope->issue(EntityType::KoreanRrn, "900101-1234567");
    ASSERT_FALSE(r);
    EXPECT_EQ(r.error(), pc::ProtectionError::LabelMismatch);
}

TEST(VaultClientE2E, DroppedScopeCannotResolve) {
    auto process = pv::VaultProcess::spawn({PA_VAULT_EXE, {}, 10000ms});
    ASSERT_TRUE(process);
    pv::ConnectionOptions opts;
    opts.stream.expected_server_pid = process->ready().pid;
    auto conn = pv::VaultConnection::connect(process->ready().endpoint, process->ready().secret, opts);
    ASSERT_TRUE(conn);
    auto scope = conn->create_scope(60000ms);
    ASSERT_TRUE(scope);
    auto token = conn->create_token(*scope, "PERSON", "가상인");
    ASSERT_TRUE(token);
    ASSERT_TRUE(conn->drop_scope(*scope));
    const auto r = conn->resolve_exact(*scope, *token);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.error().code, pv::ErrorCode::ScopeNotFound);
    EXPECT_FALSE(conn->broken());
}

TEST(VaultClientE2E, WrongSecretAndWrongServerAreRejected) {
    auto process = pv::VaultProcess::spawn({PA_VAULT_EXE, {}, 10000ms});
    ASSERT_TRUE(process);
    // 다른 Vault 의 비밀값으로는 인증되지 않는다.
    auto other = pv::VaultProcess::spawn({PA_VAULT_EXE, {}, 10000ms});
    ASSERT_TRUE(other);
    auto bad = pv::VaultConnection::connect(process->ready().endpoint, other->ready().secret, {});
    ASSERT_FALSE(bad);
    EXPECT_EQ(bad.error().code, pv::ErrorCode::AuthFailed);
    // 서버 pid 가 기대와 다르면 연결하지 않는다.
    pv::ConnectionOptions opts;
    opts.stream.expected_server_pid = other->ready().pid;
    auto spoofed = pv::VaultConnection::connect(process->ready().endpoint, process->ready().secret, opts);
    ASSERT_FALSE(spoofed);
    EXPECT_EQ(spoofed.error().code, pv::ErrorCode::ServerIdentityMismatch);
}

TEST(VaultClientE2E, StdinCloseStopsVault) {
    auto process = pv::VaultProcess::spawn({PA_VAULT_EXE, {}, 10000ms});
    ASSERT_TRUE(process);
    process->close_stdin();
    EXPECT_TRUE(process->wait_exit(10000ms));
}

TEST(VaultClientE2E, KilledVaultFailsClosedThenRestarts) {
    pv::VaultService service(options());
    auto scope = service.open_scope();
    ASSERT_TRUE(scope);
    const auto token = scope->issue(EntityType::Email, "user1@example.invalid");
    ASSERT_TRUE(token);
    const auto pid = service.vault_pid();
    ASSERT_TRUE(pid);
    kill_process(*pid);

    // 죽은 세대의 범위로는 발급도 복원도 되지 않는다.
    const auto issued = scope->issue(EntityType::Email, "user2@example.invalid");
    ASSERT_FALSE(issued);
    EXPECT_EQ(issued.error(), pc::ProtectionError::IssuerUnavailable);
    const auto resolved = scope->resolve(*token);
    ASSERT_FALSE(resolved);
    EXPECT_EQ(resolved.error(), pc::RestoreError::ResolverUnavailable);

    // 다음 요청은 새 Vault 로 성공하고, 예전 token 은 새 Vault 에 없다.
    auto next = service.open_scope();
    ASSERT_TRUE(next) << pv::to_string(next.error().code);
    EXPECT_NE(service.vault_pid(), pid);
    const auto stale = next->resolve(*token);
    ASSERT_FALSE(stale);
    EXPECT_EQ(stale.error(), pc::RestoreError::TokenNotFound);
}

TEST(VaultClientE2E, RestartWaitsForTheDelay) {
    pv::VaultService service(options(60000ms));
    auto scope = service.open_scope();
    ASSERT_TRUE(scope);
    const auto pid = service.vault_pid();
    ASSERT_TRUE(pid);
    kill_process(*pid);
    ASSERT_FALSE(scope->issue(EntityType::Email, "user1@example.invalid"));  // 죽음을 알아챈다
    const auto next = service.open_scope();
    ASSERT_FALSE(next);
    EXPECT_EQ(next.error().code, pv::ErrorCode::RestartPending);
}

TEST(VaultClientE2E, ConcurrentScopesShareOneService) {
    auto o = options();
    o.pool_size = 4;
    pv::VaultService service(o);
    constexpr int threads = 8;
    constexpr int rounds = 25;
    std::vector<std::thread> workers;
    std::vector<int> failures(threads, 0);
    for (int t = 0; t < threads; ++t) {
        workers.emplace_back([&, t] {
            for (int i = 0; i < rounds; ++i) {
                auto scope = service.open_scope();
                if (!scope) {
                    ++failures[static_cast<std::size_t>(t)];
                    continue;
                }
                const std::string value = "user" + std::to_string(t) + "-" + std::to_string(i) + "@example.invalid";
                const auto token = scope->issue(EntityType::Email, value);
                const auto back = token ? scope->resolve(*token) : std::unexpected(pc::RestoreError::ResolverUnavailable);
                if (!back || back->view() != value) {
                    ++failures[static_cast<std::size_t>(t)];
                }
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }
    for (int t = 0; t < threads; ++t) {
        EXPECT_EQ(failures[static_cast<std::size_t>(t)], 0) << "thread " << t;
    }
}
