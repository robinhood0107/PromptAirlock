// TLS 설정 시험: 키·인증서 검사와, 메모리 BIO 쌍으로 붙인 실제 handshake 로 협상 범위(ADR 0014)를 확인한다.
#include "prompt_airlock/tls/context.hpp"

#include "test_cert.hpp"

#include <gtest/gtest.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <memory>
#include <optional>
#include <string>

namespace {

namespace tls = prompt_airlock::tls;
using pa_test::make_test_certificate;
using pa_test::TestKey;

struct SslFree {
    void operator()(SSL* p) const noexcept { SSL_free(p); }
};
struct CtxFree {
    void operator()(SSL_CTX* p) const noexcept { SSL_CTX_free(p); }
};
using RawCtx = std::unique_ptr<SSL_CTX, CtxFree>;

struct Outcome {
    bool ok = false;
    std::string version;
    std::string cipher;
};

// 서버와 클라이언트를 메모리 BIO 쌍으로 이어 handshake 가 끝날 때까지 번갈아 돌린다.
Outcome handshake(SSL_CTX* server_ctx, SSL_CTX* client_ctx) {
    std::unique_ptr<SSL, SslFree> server(SSL_new(server_ctx));
    std::unique_ptr<SSL, SslFree> client(SSL_new(client_ctx));
    BIO* server_bio = nullptr;
    BIO* client_bio = nullptr;
    if (!server || !client || BIO_new_bio_pair(&server_bio, 0, &client_bio, 0) != 1) {
        return {};
    }
    SSL_set_bio(server.get(), server_bio, server_bio);
    SSL_set_bio(client.get(), client_bio, client_bio);
    SSL_set_accept_state(server.get());
    SSL_set_connect_state(client.get());
    SSL_set_tlsext_host_name(client.get(), "localhost");
    SSL_set1_host(client.get(), "localhost");

    const auto pending = [](SSL* ssl, int rc) {
        const int e = SSL_get_error(ssl, rc);
        return e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE;
    };
    for (int round = 0; round < 32; ++round) {
        const int rc = SSL_do_handshake(client.get());
        const int rs = SSL_do_handshake(server.get());
        if (rc == 1 && rs == 1) {
            return {true, SSL_get_version(client.get()), SSL_get_cipher_name(client.get())};
        }
        if ((rc != 1 && !pending(client.get(), rc)) || (rs != 1 && !pending(server.get(), rs))) {
            break;
        }
    }
    ERR_clear_error();
    return {};
}

// 협상 범위를 시험마다 직접 고르는 클라이언트(일부러 금지된 설정을 내미는 상대 역할).
RawCtx raw_client(int min_version, int max_version, const char* tls12_ciphers, const char* tls13_suites,
                  const char* groups = nullptr) {
    RawCtx ctx(SSL_CTX_new(TLS_client_method()));
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_min_proto_version(ctx.get(), min_version);
    SSL_CTX_set_max_proto_version(ctx.get(), max_version);
    if (tls12_ciphers != nullptr) {
        SSL_CTX_set_cipher_list(ctx.get(), tls12_ciphers);
    }
    if (tls13_suites != nullptr) {
        SSL_CTX_set_ciphersuites(ctx.get(), tls13_suites);
    }
    if (groups != nullptr) {
        SSL_CTX_set1_groups_list(ctx.get(), groups);
    }
    return ctx;
}

TEST(TlsContext, ServerAcceptsEcP256AndRsa2048) {
    for (const TestKey key : {TestKey::EcP256, TestKey::Rsa2048}) {
        const auto cert = make_test_certificate(key);
        ASSERT_FALSE(cert.certificate_pem.empty());
        EXPECT_TRUE(tls::make_server_context(cert.certificate_pem, cert.private_key_pem).has_value());
    }
}

TEST(TlsContext, ServerRejectsWeakKeys) {
    for (const TestKey key : {TestKey::EcP521, TestKey::Rsa1024}) {
        const auto cert = make_test_certificate(key);
        ASSERT_FALSE(cert.certificate_pem.empty());
        const auto ctx = tls::make_server_context(cert.certificate_pem, cert.private_key_pem);
        ASSERT_FALSE(ctx.has_value());
        EXPECT_EQ(ctx.error(), tls::TlsError::WeakKey);
    }
}

TEST(TlsContext, ServerRejectsBrokenOrMismatchedInput) {
    const auto a = make_test_certificate();
    const auto b = make_test_certificate();
    const auto mismatched = tls::make_server_context(a.certificate_pem, b.private_key_pem);
    ASSERT_FALSE(mismatched.has_value());
    EXPECT_EQ(mismatched.error(), tls::TlsError::InvalidKey);

    const auto no_cert = tls::make_server_context("not a certificate", a.private_key_pem);
    ASSERT_FALSE(no_cert.has_value());
    EXPECT_EQ(no_cert.error(), tls::TlsError::InvalidCertificate);

    const auto no_key = tls::make_server_context(a.certificate_pem, "");
    ASSERT_FALSE(no_key.has_value());
    EXPECT_EQ(no_key.error(), tls::TlsError::InvalidKey);
}

TEST(TlsContext, ClientRejectsEmptyTrustStore) {
    const auto ctx = tls::make_client_context(std::string_view{"no certificates here"});
    ASSERT_FALSE(ctx.has_value());
    EXPECT_EQ(ctx.error(), tls::TlsError::InvalidTrustStore);
}

class TlsHandshake : public ::testing::Test {
protected:
    void SetUp() override {
        cert_ = make_test_certificate();
        ASSERT_FALSE(cert_.certificate_pem.empty());
        auto server = tls::make_server_context(cert_.certificate_pem, cert_.private_key_pem);
        ASSERT_TRUE(server.has_value());
        server_.emplace(std::move(*server));
    }
    SSL_CTX* server() { return server_->native_handle(); }

    pa_test::TestCertificate cert_;
    std::optional<boost::asio::ssl::context> server_;
};

TEST_F(TlsHandshake, OwnClientAndServerAgreeOnTls13AesGcm) {
    auto client = tls::make_client_context(std::string_view{cert_.certificate_pem});
    ASSERT_TRUE(client.has_value());
    const auto out = handshake(server(), client->native_handle());
    ASSERT_TRUE(out.ok);
    EXPECT_EQ(out.version, "TLSv1.3");
    EXPECT_NE(out.cipher.find("AES"), std::string::npos);
    EXPECT_NE(out.cipher.find("GCM"), std::string::npos);
}

TEST_F(TlsHandshake, ClientRefusesUntrustedServer) {
    const auto other = make_test_certificate();
    auto client = tls::make_client_context(std::string_view{other.certificate_pem});
    ASSERT_TRUE(client.has_value());
    EXPECT_FALSE(handshake(server(), client->native_handle()).ok);
}

TEST_F(TlsHandshake, Tls12WithEcdheAesGcmIsAccepted) {
    const auto client = raw_client(TLS1_2_VERSION, TLS1_2_VERSION, "ECDHE-ECDSA-AES256-GCM-SHA384", nullptr);
    const auto out = handshake(server(), client.get());
    ASSERT_TRUE(out.ok);
    EXPECT_EQ(out.version, "TLSv1.2");
    EXPECT_EQ(out.cipher, "ECDHE-ECDSA-AES256-GCM-SHA384");
}

TEST_F(TlsHandshake, ForbiddenNegotiationsFail) {
    // ChaCha20 만 내미는 상대(TLS 1.3, TLS 1.2 각각)
    EXPECT_FALSE(handshake(server(), raw_client(TLS1_3_VERSION, TLS1_3_VERSION, nullptr,
                                                "TLS_CHACHA20_POLY1305_SHA256")
                                         .get())
                     .ok);
    EXPECT_FALSE(handshake(server(), raw_client(TLS1_2_VERSION, TLS1_2_VERSION,
                                                "ECDHE-ECDSA-CHACHA20-POLY1305", nullptr)
                                         .get())
                     .ok);
    // CBC 묶음만 내미는 TLS 1.2 상대
    EXPECT_FALSE(handshake(server(), raw_client(TLS1_2_VERSION, TLS1_2_VERSION,
                                                "ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA", nullptr)
                                         .get())
                     .ok);
    // TLS 1.1 이하만 아는 상대. 클라이언트 쪽 보안 수준을 0 으로 내려 서버가 거절하는지만 본다.
    EXPECT_FALSE(handshake(server(), raw_client(TLS1_VERSION, TLS1_1_VERSION, "ALL:@SECLEVEL=0", nullptr).get()).ok);
    // X25519 만 내미는 상대
    EXPECT_FALSE(handshake(server(), raw_client(TLS1_3_VERSION, TLS1_3_VERSION, nullptr, nullptr, "X25519").get()).ok);
}

}  // namespace
