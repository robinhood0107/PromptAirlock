// Vault 응답 프레임 읽기(길이 머리 4바이트 + protobuf)를 아무 바이트로 시험한다. 가짜 연결이 입력 바이트를
// 응답으로 돌려주고, 클라이언트는 인증 → 범위 만들기 → 발급 → 복원 → 범위 지우기를 차례로 부른다.
// 죽지 않아야 하고, 한 번 broken 이 된 연결은 다시 성공하면 안 된다(fail closed).
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>

#include "prompt_airlock/vault_client/connection.hpp"

namespace pv = prompt_airlock::vault_client;
using namespace std::chrono_literals;

namespace {

// 쓰기는 버리고, 읽기는 fuzz 입력을 앞에서부터 내준다. 모자라면 연결이 끊긴 것으로 본다.
class ReplayStream final : public pv::ByteStream {
public:
    explicit ReplayStream(std::span<const std::uint8_t> data) : data_(data) {}
    pv::Result<void> write_all(std::span<const std::uint8_t>, std::chrono::milliseconds) override { return {}; }
    pv::Result<void> read_exact(std::span<std::uint8_t> out, std::chrono::milliseconds) override {
        if (out.size() > data_.size()) {
            return pv::fail(pv::ErrorCode::Disconnected);
        }
        std::copy_n(data_.begin(), out.size(), out.begin());
        data_ = data_.subspan(out.size());
        return {};
    }
    void close() noexcept override {}

private:
    std::span<const std::uint8_t> data_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto secret = pv::AuthSecret::from_hex(std::string(64, 'a'));
    if (!secret) {
        __builtin_trap();
    }
    pv::ConnectionOptions opts;
    opts.max_frame_bytes = 4096;
    auto conn = pv::VaultConnection::handshake(std::make_unique<ReplayStream>(std::span(data, size)), *secret, opts);
    if (!conn) {
        return 0;
    }
    bool was_broken = false;
    const auto step = [&](bool ok) {
        if (was_broken && ok) {
            __builtin_trap();  // broken 뒤에 성공하면 안 된다
        }
        was_broken = was_broken || conn->broken();
    };
    auto scope = conn->create_scope(1000ms);
    step(scope.has_value());
    if (!scope) {
        return 0;
    }
    const auto token = conn->create_token(*scope, "EMAIL", "user1@example.invalid");
    step(token.has_value());
    const auto value = conn->resolve_exact(*scope, token ? *token : std::string("x"));
    step(value.has_value());
    step(conn->drop_scope(*scope).has_value());
    return 0;
}
