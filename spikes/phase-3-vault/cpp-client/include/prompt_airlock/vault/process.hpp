// Vault 프로세스 실행·종료 RAII. CreateProcessW / posix_spawn 을 쓰며 system() 은 쓰지 않는다.
// 비밀값은 자식의 stdout 파이프(이 프로세스만 읽음)로 받는다. 자식 stdin 은 열어 두고,
// 닫으면(또는 이 프로세스가 죽으면) Vault 가 스스로 종료한다.
#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "prompt_airlock/vault/types.hpp"

namespace prompt_airlock::vault {

struct SpawnOptions {
    std::filesystem::path exe;
    std::vector<std::string> args;
    std::chrono::milliseconds ready_timeout{10000};
};

struct ReadyInfo {
    Endpoint endpoint;
    AuthSecret secret;
    std::uint64_t pid;
};

class VaultProcess {
public:
    static Result<VaultProcess> spawn(const SpawnOptions& opts);

    VaultProcess(VaultProcess&&) noexcept;
    VaultProcess& operator=(VaultProcess&&) noexcept;
    VaultProcess(const VaultProcess&) = delete;
    VaultProcess& operator=(const VaultProcess&) = delete;
    ~VaultProcess();  // 살아 있으면 강제 종료 후 회수

    const ReadyInfo& ready() const noexcept;
    // 강제 종료(TerminateProcess / SIGKILL) 후 회수.
    void kill() noexcept;
    // stdin 을 닫아 정상 종료를 요청한다.
    void close_stdin() noexcept;
    // 종료를 기다린다. 시간 안에 끝나면 true.
    bool wait_exit(std::chrono::milliseconds timeout) noexcept;

private:
    struct Impl;
    explicit VaultProcess(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};

}  // namespace prompt_airlock::vault
