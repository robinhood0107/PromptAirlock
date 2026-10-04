// transport 별 왕복 지연·처리량 측정. 실제 Vault 프로세스와 C++ 클라이언트를 쓴다. 값은 합성 데이터.
// 사용: vault_bench <vault-exe> [transport...]   transport: tcp | pipe | pipe-default | uds
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <latch>
#include <string>
#include <thread>
#include <vector>

#include "prompt_airlock/vault/client.hpp"
#include "prompt_airlock/vault/process.hpp"

using namespace prompt_airlock::vault;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

namespace {

constexpr int kIters = 2000;
constexpr int kWarmup = 200;
constexpr int kOpsPerThread = 4000;

struct Stats {
    double p50, p95, p99, mean;
};

Stats summarize(std::vector<double> us) {
    std::ranges::sort(us);
    auto pct = [&](double p) { return us[static_cast<std::size_t>(p * static_cast<double>(us.size() - 1))]; };
    double sum = 0;
    for (double v : us) sum += v;
    return {pct(0.50), pct(0.95), pct(0.99), sum / static_cast<double>(us.size())};
}

double micros(Clock::duration d) { return std::chrono::duration<double, std::micro>(d).count(); }

std::vector<std::string> args_for(const std::string& t) {
    if (t == "tcp") return {"--transport", "tcp"};
    if (t == "pipe") return {"--transport", "pipe", "--pipe-acl", "current-user"};
    if (t == "pipe-default") return {"--transport", "pipe", "--pipe-acl", "default"};
    if (t == "uds") return {"--transport", "uds"};
    return {};
}

ClientOptions opts_for(const VaultProcess& p) {
    ClientOptions o;
    o.stream.expected_server_pid = p.ready().pid;
    o.io_timeout = 5000ms;
    return o;
}

int run(const std::string& exe, const std::string& transport) {
    SpawnOptions so;
    so.exe = exe;
    so.args = args_for(transport);
    so.args.insert(so.args.end(), {"--max-mappings", "100000", "--queue", "4096"});
    const auto t_spawn = Clock::now();
    auto proc = VaultProcess::spawn(so);
    const auto spawn_us = micros(Clock::now() - t_spawn);
    if (!proc) {
        std::printf("%s: spawn failed %s\n", transport.c_str(), std::string(to_string(proc.error().code)).c_str());
        return 1;
    }
    // 연결+hello 지연
    std::vector<double> conn;
    for (int i = 0; i < 50; ++i) {
        const auto t0 = Clock::now();
        auto c = VaultClient::connect(proc->ready().endpoint, proc->ready().secret, opts_for(*proc));
        conn.push_back(micros(Clock::now() - t0));
        if (!c) return 1;
    }
    auto c = VaultClient::connect(proc->ready().endpoint, proc->ready().secret, opts_for(*proc));
    if (!c) return 1;
    auto scope = c->create_scope(600s);
    if (!scope) return 1;
    const auto label = *EntityLabel::parse("PERSON");
    std::vector<Token> tokens;
    std::vector<double> create_us, resolve_us;
    for (int i = 0; i < kWarmup + kIters; ++i) {
        const std::string v = "synthetic-person-" + std::to_string(i);
        const auto t0 = Clock::now();
        auto t = c->create_token(*scope, label, v);
        const auto dt = micros(Clock::now() - t0);
        if (!t) return 1;
        if (i >= kWarmup) {
            create_us.push_back(dt);
            tokens.push_back(std::move(*t));
        }
    }
    for (const auto& t : tokens) {
        const auto t0 = Clock::now();
        auto r = c->resolve_exact(*scope, t);
        resolve_us.push_back(micros(Clock::now() - t0));
        if (!r) return 1;
    }
    const auto cs = summarize(create_us);
    const auto rs = summarize(resolve_us);
    const auto cn = summarize(conn);
    std::printf("| %s | spawn→READY %.0f us | connect+hello p50 %.0f us |\n", transport.c_str(), spawn_us, cn.p50);
    std::printf("| %s | CreateToken | p50 %.1f | p95 %.1f | p99 %.1f | mean %.1f us (n=%d) |\n", transport.c_str(), cs.p50,
                cs.p95, cs.p99, cs.mean, kIters);
    std::printf("| %s | ResolveExact | p50 %.1f | p95 %.1f | p99 %.1f | mean %.1f us (n=%d) |\n", transport.c_str(), rs.p50,
                rs.p95, rs.p99, rs.mean, kIters);

    // 처리량: N 클라이언트, 각자 scope 하나, CreateToken/ResolveExact 교대
    for (int n : {1, 4, 8, 16}) {
        std::atomic<int> failures{0};
        std::atomic<bool> go{false};
        std::latch ready(n);
        std::vector<std::jthread> ts;
        for (int k = 0; k < n; ++k) {
            ts.emplace_back([&, k] {
                auto cl = VaultClient::connect(proc->ready().endpoint, proc->ready().secret, opts_for(*proc));
                auto s = cl ? cl->create_scope(600s) : Result<ScopeId>(fail(ErrorCode::ConnectFailed));
                ready.count_down();
                if (!s) {
                    ++failures;
                    return;
                }
                go.wait(false);
                for (int i = 0; i < kOpsPerThread / 2; ++i) {
                    auto t = cl->create_token(*s, label, "t" + std::to_string(k) + "-v" + std::to_string(i));
                    if (!t || !cl->resolve_exact(*s, *t)) {
                        ++failures;
                        return;
                    }
                }
            });
        }
        // 모든 클라이언트가 연결과 scope 생성을 마친 뒤 시간을 잰다.
        ready.wait();
        const auto t0 = Clock::now();
        go = true;
        go.notify_all();
        ts.clear();
        const double sec = std::chrono::duration<double>(Clock::now() - t0).count();
        std::printf("| %s | clients=%d | %.0f ops/s | failures=%d |\n", transport.c_str(), n,
                    static_cast<double>(n * kOpsPerThread) / sec, failures.load());
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: vault_bench <vault-exe> [tcp|pipe|pipe-default|uds ...]\n");
        return 2;
    }
    std::vector<std::string> ts(argv + 2, argv + argc);
    if (ts.empty()) {
#ifdef _WIN32
        ts = {"pipe", "pipe-default", "tcp"};
#else
        ts = {"uds", "tcp"};
#endif
    }
    int rc = 0;
    for (const auto& t : ts) rc |= run(argv[1], t);
    return rc;
}
