// 테스트 실행 중에만 쓰는 자체 서명 인증서를 OpenSSL API 로 메모리에서 만든다. 디스크에 키를 남기지 않는다.
#pragma once

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <expected>
#include <memory>
#include <string>

namespace pa_spike {

struct TestCert {
    std::string cert_pem;
    std::string key_pem;
};

namespace detail {
struct PkeyDeleter { void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); } };
struct X509Deleter { void operator()(X509* p) const noexcept { X509_free(p); } };
struct BioDeleter { void operator()(BIO* p) const noexcept { BIO_free(p); } };
struct ExtDeleter { void operator()(X509_EXTENSION* p) const noexcept { X509_EXTENSION_free(p); } };

inline std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    return std::string(data, static_cast<std::size_t>(len));
}
}  // namespace detail

// CN=localhost, SAN=DNS:localhost,IP:127.0.0.1 인 EC P-256 인증서.
inline std::expected<TestCert, std::string> make_test_cert() {
    using namespace detail;
    std::unique_ptr<EVP_PKEY, PkeyDeleter> key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
    if (!key) return std::unexpected("keygen failed");

    std::unique_ptr<X509, X509Deleter> cert(X509_new());
    if (!cert) return std::unexpected("x509 alloc failed");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60L);
    X509_set_pubkey(cert.get(), key.get());

    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
    for (const char* spec : {"DNS:localhost,IP:127.0.0.1"}) {
        std::unique_ptr<X509_EXTENSION, ExtDeleter> ext(X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, spec));
        if (!ext || X509_add_ext(cert.get(), ext.get(), -1) != 1) return std::unexpected("san failed");
    }
    std::unique_ptr<X509_EXTENSION, ExtDeleter> bc(
        X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE"));
    if (!bc || X509_add_ext(cert.get(), bc.get(), -1) != 1) return std::unexpected("bc failed");

    if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) return std::unexpected("sign failed");

    std::unique_ptr<BIO, BioDeleter> cert_bio(BIO_new(BIO_s_mem()));
    std::unique_ptr<BIO, BioDeleter> key_bio(BIO_new(BIO_s_mem()));
    if (!cert_bio || !key_bio) return std::unexpected("bio alloc failed");
    if (PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1) return std::unexpected("pem cert failed");
    if (PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        return std::unexpected("pem key failed");
    }
    return TestCert{bio_to_string(cert_bio.get()), bio_to_string(key_bio.get())};
}

}  // namespace pa_spike
