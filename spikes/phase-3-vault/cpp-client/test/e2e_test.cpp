// 실제 Vault 프로세스를 띄워 C++ 클라이언트로 검증하는 E2E 시험. 값은 모두 합성 데이터다.
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "prompt_airlock/vault/client.hpp"
#include "prompt_airlock/vault/process.hpp"
#include "prompt_airlock/vault/stream.hpp"
#include "vault_v1.pb.h"

using namespace prompt_airlock::vault;
using namespace std::chrono_literals;
namespace wire = prompt_airlock::vault::v1;

namespace {

#define PA_ASSERT_OK(r) ASSERT_TRUE((r).has_value()) << to_string((r).error().code)

std::vector<std::string> args_for(TransportKind k) {
    switch (k) {
        case TransportKind::Tcp: return {"--transport", "tcp"};
        case TransportKind::NamedPipe: return {"--transport", "pipe", "--pipe-acl", "current-user"};
        case TransportKind::UnixSocket: return {"--transport", "uds"};
    }
    return {};
}

std::string name_of(TransportKind k) {
    switch (k) {
        case TransportKind::Tcp: return "Tcp";
        case TransportKind::NamedPipe: return "NamedPipe";
        case TransportKind::UnixSocket: return "UnixSocket";
    }
    return "?";
}

Result<VaultProcess> spawn(TransportKind k, std::vector<std::string> extra = {}) {
    SpawnOptions o;
    o.exe = PA_VAULT_EXE;
    o.args = args_for(k);
    o.args.insert(o.args.end(), extra.begin(), extra.end());
    return VaultProcess::spawn(o);
}

ClientOptions opts_for(const VaultProcess& p) {
    ClientOptions o;
    o.stream.expected_server_pid = p.ready().pid;
    o.io_timeout = 3000ms;
    return o;
}

Result<VaultClient> connect(const VaultProcess& p) {
    return VaultClient::connect(p.ready().endpoint, p.ready().secret, opts_for(p));
}

EntityLabel label(std::string_view s) { return *EntityLabel::parse(s); }

bool is_transport_failure(ErrorCode c) {
    return c == ErrorCode::Disconnected || c == ErrorCode::Io || c == ErrorCode::Timeout || c == ErrorCode::ClientBroken;
}

class VaultE2E : public ::testing::TestWithParam<TransportKind> {
protected:
    void SetUp() override {
        auto p = spawn(GetParam());
        ASSERT_TRUE(p.has_value()) << to_string(p.error().code);
        proc_.emplace(std::move(*p));
        auto c = connect(*proc_);
        ASSERT_TRUE(c.has_value()) << to_string(c.error().code);
        client_.emplace(std::move(*c));
    }

    VaultClient& c() { return *client_; }
    std::optional<VaultProcess> proc_;
    std::optional<VaultClient> client_;
};

TEST_P(VaultE2E, SameValueSameTokenDifferentValueDifferentToken) {
    auto s = c().create_scope(60s);
    PA_ASSERT_OK(s);
    auto a1 = c().create_token(*s, label("PERSON"), "합성홍길동");
    auto a2 = c().create_token(*s, label("PERSON"), "합성홍길동");
    auto b = c().create_token(*s, label("PERSON"), "합성김철수");
    auto a_org = c().create_token(*s, label("ORG"), "합성홍길동");
    PA_ASSERT_OK(a1);
    PA_ASSERT_OK(a2);
    PA_ASSERT_OK(b);
    PA_ASSERT_OK(a_org);
    EXPECT_EQ(*a1, *a2);
    EXPECT_NE(*a1, *b);
    EXPECT_NE(*a1, *a_org);
}

TEST_P(VaultE2E, TokenFormatHasNoOriginal) {
    auto s = c().create_scope(60s);
    PA_ASSERT_OK(s);
    const std::string value = "synthetic.user99@example.invalid";
    auto t = c().create_token(*s, label("EMAIL"), value);
    PA_ASSERT_OK(t);
    const std::string& tok = t->str();
    EXPECT_TRUE(tok.starts_with("\xE2\x9F\xA6" "EMAIL_")) << tok;  // ⟦
    EXPECT_TRUE(tok.ends_with("\xE2\x9F\xA7")) << tok;              // ⟧
    EXPECT_EQ(tok.find(value), std::string::npos);
    for (std::size_t i = 0; i + 4 <= value.size(); ++i) {
        std::string w = value.substr(i, 4);
        std::ranges::transform(w, w.begin(), [](char ch) { return static_cast<char>(std::toupper(static_cast<unsigned char>(ch))); });
        EXPECT_EQ(tok.find(w, 3 + 6), std::string::npos) << w;
    }
}

TEST_P(VaultE2E, ResolveExactRoundtrip) {
    auto s = c().create_scope(60s);
    PA_ASSERT_OK(s);
    auto t = c().create_token(*s, label("PHONE"), "010-0000-1234");
    PA_ASSERT_OK(t);
    auto v = c().resolve_exact(*s, *t);
    PA_ASSERT_OK(v);
    EXPECT_EQ(v->view(), "010-0000-1234");
    EXPECT_EQ(v->label(), "PHONE");
}

TEST_P(VaultE2E, ModifiedTokenNeverResolves) {
    auto s = c().create_scope(60s);
    PA_ASSERT_OK(s);
    auto t = c().create_token(*s, label("PERSON"), "합성홍길동");
    PA_ASSERT_OK(t);
    const std::string tok = t->str();
    std::vector<std::string> variants;
    std::string last = tok;
    const std::size_t close_at = last.size() - 3;  // ⟧ 는 3바이트
    last[close_at - 1] = last[close_at - 1] == '0' ? '1' : '0';
    variants.push_back(last);
    std::string lower = tok;
    std::ranges::transform(lower, lower.begin(), [](char ch) { return static_cast<char>(std::tolower(static_cast<unsigned char>(ch))); });
    variants.push_back(lower);
    variants.push_back(" " + tok);
    variants.push_back(tok.substr(3, tok.size() - 6));             // 괄호 제거
    variants.push_back("[" + tok.substr(3, tok.size() - 6) + "]");  // ASCII 괄호
    variants.push_back(tok.substr(0, tok.size() - 4) + "\xE2\x9F\xA7");  // 한 글자 삭제
    std::string relabeled = tok;
    relabeled.replace(3, 6, "PERSOM");
    variants.push_back(relabeled);
    for (const auto& v : variants) {
        auto r = c().resolve_exact(*s, Token(v));
        ASSERT_FALSE(r.has_value()) << v;
        EXPECT_TRUE(r.error().code == ErrorCode::TokenNotFound || r.error().code == ErrorCode::MalformedToken)
            << to_string(r.error().code);
    }
    // 오류 뒤에도 연결은 정상이며 원래 token 은 복원된다.
    EXPECT_FALSE(c().broken());
    PA_ASSERT_OK(c().resolve_exact(*s, *t));
}

TEST_P(VaultE2E, WrongScopeFails) {
    auto a = c().create_scope(60s);
    auto b = c().create_scope(60s);
    PA_ASSERT_OK(a);
    PA_ASSERT_OK(b);
    auto ta = c().create_token(*a, label("PERSON"), "합성홍길동");
    auto tb = c().create_token(*b, label("PERSON"), "합성홍길동");
    PA_ASSERT_OK(ta);
    PA_ASSERT_OK(tb);
    EXPECT_NE(*ta, *tb);  // scope 간 상관관계 없음
    auto r = c().resolve_exact(*b, *ta);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::TokenNotFound);
    std::array<std::uint8_t, 16> ghost{};
    ghost.fill(0x11);
    auto unknown = c().resolve_exact(*ScopeId::from_bytes(ghost), *ta);
    ASSERT_FALSE(unknown.has_value());
    EXPECT_EQ(unknown.error().code, ErrorCode::ScopeNotFound);
}

TEST_P(VaultE2E, TtlExpiry) {
    auto s = c().create_scope(300ms);
    PA_ASSERT_OK(s);
    const auto created = std::chrono::steady_clock::now();
    auto t = c().create_token(*s, label("PERSON"), "합성홍길동");
    PA_ASSERT_OK(t);
    PA_ASSERT_OK(c().resolve_exact(*s, *t));
    // TTL 은 벽시계 경과로만 검증할 수 있다. 동기화가 아니라 시간 경과 자체가 시험 대상이다.
    std::this_thread::sleep_until(created + 400ms);
    auto r = c().resolve_exact(*s, *t);
    ASSERT_FALSE(r.has_value());
    EXPECT_TRUE(r.error().code == ErrorCode::ScopeExpired || r.error().code == ErrorCode::ScopeNotFound)
        << to_string(r.error().code);
    auto again = c().create_token(*s, label("PERSON"), "합성홍길동");
    ASSERT_FALSE(again.has_value());
}

TEST_P(VaultE2E, DropScopeThenResolveFails) {
    auto s = c().create_scope(60s);
    PA_ASSERT_OK(s);
    auto t = c().create_token(*s, label("PERSON"), "합성홍길동");
    PA_ASSERT_OK(t);
    PA_ASSERT_OK(c().drop_scope(*s));
    auto r = c().resolve_exact(*s, *t);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::ScopeNotFound);
    auto d = c().drop_scope(*s);
    ASSERT_FALSE(d.has_value());
    EXPECT_EQ(d.error().code, ErrorCode::ScopeNotFound);
}

TEST_P(VaultE2E, ScopeGuardDropsOnScopeExit) {
    std::optional<ScopeId> id;
    std::optional<Token> tok;
    {
        auto s = c().create_scope(60s);
        PA_ASSERT_OK(s);
        ScopeGuard g(c(), *s);
        id = g.id();
        auto t = c().create_token(g.id(), label("PERSON"), "합성홍길동");
        PA_ASSERT_OK(t);
        tok = *t;
    }
    auto r = c().resolve_exact(*id, *tok);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::ScopeNotFound);
}

TEST_P(VaultE2E, LimitsAreTypedErrors) {
    auto s = c().create_scope(60s);
    PA_ASSERT_OK(s);
    auto big = c().create_token(*s, label("BLOB"), std::string(5000, 'x'));
    ASSERT_FALSE(big.has_value());
    EXPECT_EQ(big.error().code, ErrorCode::ValueTooLarge);
    auto empty = c().create_token(*s, label("BLOB"), "");
    ASSERT_FALSE(empty.has_value());
    EXPECT_EQ(empty.error().code, ErrorCode::InvalidArgument);
    auto long_ttl = c().create_scope(std::chrono::hours(2));
    ASSERT_FALSE(long_ttl.has_value());
    EXPECT_EQ(long_ttl.error().code, ErrorCode::InvalidArgument);
    EXPECT_FALSE(EntityLabel::parse("person").has_value());
    EXPECT_FALSE(c().broken());
}

TEST_P(VaultE2E, ConcurrentScopesNoCrossTalk) {
    constexpr int kThreads = 8;
    constexpr int kValues = 100;
    struct Out {
        std::optional<ScopeId> scope;
        std::map<std::string, std::string> tokens;  // value -> token
        std::string error;
    };
    std::vector<Out> outs(kThreads);
    {
        std::vector<std::jthread> ts;
        for (int i = 0; i < kThreads; ++i) {
            ts.emplace_back([&, i] {
                auto& o = outs[static_cast<std::size_t>(i)];
                auto cl = connect(*proc_);
                if (!cl) {
                    o.error = "connect";
                    return;
                }
                auto s = cl->create_scope(60s);
                if (!s) {
                    o.error = "scope";
                    return;
                }
                o.scope = *s;
                for (int k = 0; k < kValues * 2; ++k) {
                    const std::string v = "t" + std::to_string(i) + "-synthetic-" + std::to_string(k % kValues);
                    auto t = cl->create_token(*s, label("PERSON"), v);
                    if (!t) {
                        o.error = std::string("token ") + std::string(to_string(t.error().code));
                        return;
                    }
                    auto [it, inserted] = o.tokens.emplace(v, t->str());
                    if (!inserted && it->second != t->str()) {
                        o.error = "token changed";
                        return;
                    }
                }
                for (const auto& [v, t] : o.tokens) {
                    auto r = cl->resolve_exact(*s, Token(t));
                    if (!r || r->view() != v) {
                        o.error = "resolve mismatch";
                        return;
                    }
                }
            });
        }
    }
    for (const auto& o : outs) {
        ASSERT_TRUE(o.error.empty()) << o.error;
        ASSERT_EQ(o.tokens.size(), static_cast<std::size_t>(kValues));
    }
    // 다른 스레드 scope 의 token 은 내 scope 에서 복원되지 않는다.
    for (int i = 0; i < kThreads; ++i) {
        const auto& mine = outs[static_cast<std::size_t>(i)];
        const auto& other = outs[static_cast<std::size_t>((i + 1) % kThreads)];
        int checked = 0;
        for (const auto& [v, t] : other.tokens) {
            auto r = c().resolve_exact(*mine.scope, Token(t));
            ASSERT_FALSE(r.has_value());
            EXPECT_EQ(r.error().code, ErrorCode::TokenNotFound);
            if (++checked == 10) break;
        }
    }
}

TEST_P(VaultE2E, KilledVaultFailsClosed) {
    auto s = c().create_scope(60s);
    PA_ASSERT_OK(s);
    auto t = c().create_token(*s, label("PERSON"), "합성홍길동");
    PA_ASSERT_OK(t);
    proc_->kill();
    const auto start = std::chrono::steady_clock::now();
    auto r = c().resolve_exact(*s, *t);
    const auto took = std::chrono::steady_clock::now() - start;
    ASSERT_FALSE(r.has_value());  // 추측 값을 돌려주지 않는다
    EXPECT_TRUE(is_transport_failure(r.error().code)) << to_string(r.error().code);
    EXPECT_LT(took, 5s);
    EXPECT_TRUE(c().broken());
    auto again = c().create_token(*s, label("PERSON"), "합성홍길동");
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(again.error().code, ErrorCode::ClientBroken);
    // 죽은 엔드포인트로 새 연결도 실패한다.
    auto re = connect(*proc_);
    ASSERT_FALSE(re.has_value());
}

TEST_P(VaultE2E, RestartLosesAllMappings) {
    auto s = c().create_scope(60s);
    PA_ASSERT_OK(s);
    auto t = c().create_token(*s, label("PERSON"), "합성홍길동");
    PA_ASSERT_OK(t);
    const Endpoint old_ep = proc_->ready().endpoint;
    client_.reset();
    proc_->kill();
    auto p2 = spawn(GetParam());
    PA_ASSERT_OK(p2);
    EXPECT_NE(p2->ready().endpoint.address, old_ep.address);
    auto c2 = connect(*p2);
    PA_ASSERT_OK(c2);
    auto r = c2->resolve_exact(*s, *t);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::ScopeNotFound);
    // 같은 값을 새 scope 에 넣어도 이전 token 과 무관하다.
    auto s2 = c2->create_scope(60s);
    PA_ASSERT_OK(s2);
    auto t2 = c2->create_token(*s2, label("PERSON"), "합성홍길동");
    PA_ASSERT_OK(t2);
    EXPECT_NE(*t2, *t);
    // 이전 엔드포인트로는 연결되지 않는다.
    ClientOptions o;
    o.stream.connect_timeout = 500ms;
    auto old = VaultClient::connect(old_ep, p2->ready().secret, o);
    ASSERT_FALSE(old.has_value());
}

TEST_P(VaultE2E, WrongSecretRejected) {
    // 다른 Vault 실행의 비밀값으로는 인증되지 않는다.
    auto other = spawn(GetParam());
    PA_ASSERT_OK(other);
    auto r = VaultClient::connect(proc_->ready().endpoint, other->ready().secret, opts_for(*proc_));
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::AuthFailed);
}

TEST_P(VaultE2E, ServerIdentityMismatchRejected) {
    if (GetParam() == TransportKind::Tcp) {
        GTEST_SKIP() << "TCP 는 서버 프로세스 신원 확인 수단이 없다";
    }
    ClientOptions o;
    o.stream.expected_server_pid = proc_->ready().pid + 1;
    auto r = VaultClient::connect(proc_->ready().endpoint, proc_->ready().secret, o);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::ServerIdentityMismatch);
}

// 저수준 스트림으로 비정상 frame 을 보내고 오류 응답 하나를 읽는다.
std::optional<wire::Response> raw_exchange(const VaultProcess& p, const std::vector<std::uint8_t>& bytes) {
    StreamOptions so;
    auto s = open_stream(p.ready().endpoint, so);
    if (!s) return std::nullopt;
    if (!(*s)->write_all(bytes, 2000ms)) return std::nullopt;
    std::array<std::uint8_t, 4> hdr{};
    if (!(*s)->read_exact(hdr, 3000ms)) return std::nullopt;
    const std::size_t len = (std::size_t{hdr[0]} << 24) | (std::size_t{hdr[1]} << 16) | (std::size_t{hdr[2]} << 8) | hdr[3];
    if (len > 4096) return std::nullopt;
    std::string body(len, '\0');
    if (!(*s)->read_exact({reinterpret_cast<std::uint8_t*>(body.data()), len}, 2000ms)) return std::nullopt;
    wire::Response r;
    if (!r.ParseFromString(body)) return std::nullopt;
    // 서버가 연결을 닫았는지 확인한다.
    std::array<std::uint8_t, 1> one{};
    auto after = (*s)->read_exact(one, 2000ms);
    if (after.has_value()) return std::nullopt;
    return r;
}

std::vector<std::uint8_t> framed(const std::string& body) {
    std::vector<std::uint8_t> v{static_cast<std::uint8_t>(body.size() >> 24), static_cast<std::uint8_t>(body.size() >> 16),
                                static_cast<std::uint8_t>(body.size() >> 8), static_cast<std::uint8_t>(body.size())};
    v.insert(v.end(), body.begin(), body.end());
    return v;
}

TEST_P(VaultE2E, OversizedFrameRejectedWithoutCrash) {
    auto r = raw_exchange(*proc_, {0x7f, 0xff, 0xff, 0xff});
    ASSERT_TRUE(r.has_value());
    ASSERT_TRUE(r->has_error());
    EXPECT_EQ(r->error().code(), wire::FRAME_TOO_LARGE);
    // 기존 연결과 Vault 는 계속 동작한다.
    PA_ASSERT_OK(c().create_scope(1s));
}

TEST_P(VaultE2E, BadVersionRejected) {
    wire::Request req;
    req.set_protocol_version(static_cast<wire::ProtocolVersion>(2));
    req.set_request_id(9);
    req.mutable_create_scope()->set_ttl_ms(1000);
    auto r = raw_exchange(*proc_, framed(req.SerializeAsString()));
    ASSERT_TRUE(r.has_value());
    ASSERT_TRUE(r->has_error());
    EXPECT_EQ(r->error().code(), wire::UNSUPPORTED_VERSION);
    PA_ASSERT_OK(c().create_scope(1s));
}

TEST_P(VaultE2E, GarbageBytesRejected) {
    std::vector<std::uint8_t> garbage{0, 0, 0, 8, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8};
    auto r = raw_exchange(*proc_, garbage);
    ASSERT_TRUE(r.has_value());
    ASSERT_TRUE(r->has_error());
    EXPECT_EQ(r->error().code(), wire::MALFORMED_REQUEST);
    // 인증 전 op 는 AUTH_REQUIRED 후 종료
    wire::Request req;
    req.set_protocol_version(wire::PROTOCOL_VERSION_V1);
    req.set_request_id(1);
    req.mutable_create_scope()->set_ttl_ms(1000);
    auto r2 = raw_exchange(*proc_, framed(req.SerializeAsString()));
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(r2->error().code(), wire::AUTH_REQUIRED);
    // 잘린 frame 후 연결 종료: Vault 는 살아 있어야 한다
    {
        auto s = open_stream(proc_->ready().endpoint, {});
        PA_ASSERT_OK(s);
        std::vector<std::uint8_t> partial{0, 0, 0, 100, 1, 2, 3};
        PA_ASSERT_OK((*s)->write_all(partial, 1000ms));
    }
    PA_ASSERT_OK(c().create_scope(1s));
    auto fresh = connect(*proc_);
    PA_ASSERT_OK(fresh);
}

TEST_P(VaultE2E, StdinEofStopsVault) {
    client_.reset();
    proc_->close_stdin();
    EXPECT_TRUE(proc_->wait_exit(5s));
}

std::vector<TransportKind> transports() {
#ifdef _WIN32
    return {TransportKind::NamedPipe, TransportKind::Tcp};
#else
    return {TransportKind::UnixSocket, TransportKind::Tcp};
#endif
}

INSTANTIATE_TEST_SUITE_P(Transports, VaultE2E, ::testing::ValuesIn(transports()),
                         [](const auto& info) { return name_of(info.param); });

}  // namespace
