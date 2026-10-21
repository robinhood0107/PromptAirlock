// 시험 전용 자체 서명 인증서. 실행할 때마다 새 키를 만들어 메모리에서만 쓴다(저장소에 키를 두지 않는다).
#pragma once

#include <string>

namespace pa_test {

struct TestCertificate {
    std::string certificate_pem;
    std::string private_key_pem;
};

enum class TestKey { EcP256, EcP521, Rsa2048, Rsa1024 };

// subject CN 과 subjectAltName DNS·IP 는 localhost, 127.0.0.1 이다. 실패하면 빈 문자열.
[[nodiscard]] TestCertificate make_test_certificate(TestKey key = TestKey::EcP256);

}  // namespace pa_test
