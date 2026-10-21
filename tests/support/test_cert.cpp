#include "test_cert.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>

namespace pa_test {
namespace {

struct KeyFree {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct CertFree {
    void operator()(X509* p) const noexcept { X509_free(p); }
};
struct BioFree {
    void operator()(BIO* p) const noexcept { BIO_free(p); }
};
struct ExtFree {
    void operator()(X509_EXTENSION* p) const noexcept { X509_EXTENSION_free(p); }
};

std::unique_ptr<EVP_PKEY, KeyFree> generate(TestKey key) {
    switch (key) {
        case TestKey::EcP256:
            return std::unique_ptr<EVP_PKEY, KeyFree>(EVP_EC_gen("P-256"));
        case TestKey::EcP521:
            return std::unique_ptr<EVP_PKEY, KeyFree>(EVP_EC_gen("P-521"));
        case TestKey::Rsa2048:
            return std::unique_ptr<EVP_PKEY, KeyFree>(EVP_RSA_gen(2048));
        case TestKey::Rsa1024:
            return std::unique_ptr<EVP_PKEY, KeyFree>(EVP_RSA_gen(1024));
    }
    return nullptr;
}

std::string drain(BIO* bio) {
    char* data = nullptr;
    const long n = BIO_get_mem_data(bio, &data);
    return n > 0 ? std::string(data, static_cast<std::size_t>(n)) : std::string{};
}

}  // namespace

TestCertificate make_test_certificate(TestKey key_kind) {
    auto key = generate(key_kind);
    std::unique_ptr<X509, CertFree> cert(X509_new());
    if (!key || !cert) {
        return {};
    }
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60 * 24);
    X509_set_pubkey(cert.get(), key.get());
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
    std::unique_ptr<X509_EXTENSION, ExtFree> san(
        X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1"));
    std::unique_ptr<X509_EXTENSION, ExtFree> ca(X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE"));
    if (!san || !ca || X509_add_ext(cert.get(), san.get(), -1) != 1 || X509_add_ext(cert.get(), ca.get(), -1) != 1 ||
        X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) {
        return {};
    }
    std::unique_ptr<BIO, BioFree> cert_bio(BIO_new(BIO_s_mem()));
    std::unique_ptr<BIO, BioFree> key_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509(cert_bio.get(), cert.get());
    PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr);
    return {drain(cert_bio.get()), drain(key_bio.get())};
}

}  // namespace pa_test
