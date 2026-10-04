// 바이트 스트림 추상화. transport 별 구현은 stream.cpp(Boost.Asio)에 있다.
// 모든 I/O 는 timeout 을 받는다. timeout·오류가 나면 스트림은 더 쓰지 않는다(호출자가 폐기).
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include "prompt_airlock/vault/types.hpp"

namespace prompt_airlock::vault {

struct StreamOptions {
    std::chrono::milliseconds connect_timeout{2000};
    // 서버 프로세스 신원 확인. pipe 는 GetNamedPipeServerProcessId, uds 는 SO_PEERCRED 로 비교한다.
    // tcp 는 확인 수단이 없어 무시된다(보고서 참고).
    std::optional<std::uint64_t> expected_server_pid;
};

class ByteStream {
public:
    virtual ~ByteStream() = default;
    virtual Result<void> write_all(std::span<const std::uint8_t> data, std::chrono::milliseconds timeout) = 0;
    virtual Result<void> read_exact(std::span<std::uint8_t> out, std::chrono::milliseconds timeout) = 0;
    virtual void close() noexcept = 0;
};

Result<std::unique_ptr<ByteStream>> open_stream(const Endpoint& ep, const StreamOptions& opts);

}  // namespace prompt_airlock::vault
