#include "prompt_airlock/tls/context.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>

namespace prompt_airlock::tls {
namespace {

namespace ssl = boost::asio::ssl;

// ADR 0014 협상 범위. TLS 1.3 묶음은 AES-GCM 두 가지, TLS 1.2 는 ECDHE + AES-GCM 만.
constexpr const char* tls13_suites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
constexpr const char* tls12_ciphers =
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384";
constexpr const char* groups = "P-256:P-384";
// handshake 서명: ECDSA, RSA-PSS. SHA-1 과 PKCS#1 v1.5 서명은 넣지 않는다.
constexpr const char* signature_algorithms =
    "ECDSA+SHA256:ECDSA+SHA384:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_pss_sha256:rsa_pss_pss_sha384";

struct BioDeleter {
    void operator()(BIO* p) const noexcept { BIO_free(p); }
};
struct KeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct CertDeleter {
    void operator()(X509* p) const noexcept { X509_free(p); }
};

[[nodiscard]] std::unique_ptr<BIO, BioDeleter> memory_bio(std::string_view pem) {
    return std::unique_ptr<BIO, BioDeleter>(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
}

// 공통 협상 범위를 건다. 하나라도 실패하면 false.
[[nodiscard]] bool restrict_negotiation(SSL_CTX* ctx) noexcept {
    return SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 1 &&
           SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1 &&
           SSL_CTX_set_ciphersuites(ctx, tls13_suites) == 1 && SSL_CTX_set_cipher_list(ctx, tls12_ciphers) == 1 &&
           SSL_CTX_set1_groups_list(ctx, groups) == 1 && SSL_CTX_set1_sigalgs_list(ctx, signature_algorithms) == 1;
}

// 키 강도: RSA 는 2048비트 이상, EC 는 P-256·P-384 만.
[[nodiscard]] bool strong_enough(EVP_PKEY* key) noexcept {
    if (EVP_PKEY_is_a(key, "RSA") == 1 || EVP_PKEY_is_a(key, "RSA-PSS") == 1) {
        return EVP_PKEY_get_bits(key) >= 2048;
    }
    if (EVP_PKEY_is_a(key, "EC") == 1) {
        char name[32] = {};
        std::size_t len = 0;
        if (EVP_PKEY_get_utf8_string_param(key, "group", name, sizeof name, &len) != 1) {
            return false;
        }
        const std::string_view group(name, len);
        return group == "prime256v1" || group == "P-256" || group == "secp384r1" || group == "P-384";
    }
    return false;
}

}  // namespace

std::expected<ssl::context, TlsError> make_server_context(std::string_view certificate_chain_pem,
                                                          std::string_view private_key_pem) {
    ssl::context ctx(ssl::context::tls_server);
    SSL_CTX* native = ctx.native_handle();
    if (!restrict_negotiation(native)) {
        return std::unexpected(TlsError::Setup);
    }
    SSL_CTX_set_options(native, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);

    // 인증서 체인: 첫 인증서는 서버 인증서, 나머지는 중간 인증기관.
    auto cert_bio = memory_bio(certificate_chain_pem);
    std::unique_ptr<X509, CertDeleter> leaf(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
    if (!leaf) {
        return std::unexpected(TlsError::InvalidCertificate);
    }
    // 키 강도는 인증서의 공개키로 먼저 본다. OpenSSL 이 약한 키 인증서를 다른 이유로 거절하기 전에 원인을 분명히 한다.
    if (!strong_enough(X509_get0_pubkey(leaf.get()))) {
        return std::unexpected(TlsError::WeakKey);
    }
    if (SSL_CTX_use_certificate(native, leaf.get()) != 1) {
        return std::unexpected(TlsError::InvalidCertificate);
    }
    while (X509* extra = PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr)) {
        if (SSL_CTX_add_extra_chain_cert(native, extra) != 1) {  // 성공하면 ctx 가 소유한다
            X509_free(extra);
            return std::unexpected(TlsError::InvalidCertificate);
        }
    }

    auto key_bio = memory_bio(private_key_pem);
    std::unique_ptr<EVP_PKEY, KeyDeleter> key(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
    if (!key) {
        return std::unexpected(TlsError::InvalidKey);
    }
    if (SSL_CTX_use_PrivateKey(native, key.get()) != 1 || SSL_CTX_check_private_key(native) != 1) {
        return std::unexpected(TlsError::InvalidKey);
    }
    return ctx;
}

std::expected<ssl::context, TlsError> make_client_context(std::optional<std::string_view> trust_pem) {
    ssl::context ctx(ssl::context::tls_client);
    SSL_CTX* native = ctx.native_handle();
    if (!restrict_negotiation(native)) {
        return std::unexpected(TlsError::Setup);
    }
    SSL_CTX_set_options(native, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_verify(native, SSL_VERIFY_PEER, nullptr);
    if (!trust_pem) {
        if (SSL_CTX_set_default_verify_paths(native) != 1) {
            return std::unexpected(TlsError::InvalidTrustStore);
        }
        return ctx;
    }
    X509_STORE* store = SSL_CTX_get_cert_store(native);
    auto bio = memory_bio(*trust_pem);
    int added = 0;
    while (X509* ca = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) {
        const bool ok = X509_STORE_add_cert(store, ca) == 1;
        X509_free(ca);
        if (!ok) {
            return std::unexpected(TlsError::InvalidTrustStore);
        }
        ++added;
    }
    if (added == 0) {
        return std::unexpected(TlsError::InvalidTrustStore);
    }
    return ctx;
}

std::optional<int> certificate_days_left(std::string_view certificate_chain_pem) {
    auto bio = memory_bio(certificate_chain_pem);
    std::unique_ptr<X509, CertDeleter> leaf(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    int days = 0;
    int seconds = 0;
    if (!leaf || ASN1_TIME_diff(&days, &seconds, nullptr, X509_get0_notAfter(leaf.get())) != 1) {
        return std::nullopt;
    }
    return days;
}

}  // namespace prompt_airlock::tls
