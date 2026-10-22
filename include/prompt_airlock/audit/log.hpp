// 감사 기록(ADR 0021). 로컬 파일 JSON lines, 하루 단위 세그먼트, 줄마다 앞 줄 해시를 이어 붙인다.
// 원문·대응·자격 증명은 넣지 않는다(호출하는 쪽 책임, 시험으로 확인). 여러 스레드가 함께 쓴다.
#pragma once

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace prompt_airlock::audit {

using Clock = std::chrono::system_clock;

enum class AuditError : std::uint8_t {
    Io,           // 폴더·파일을 열거나 쓸 수 없음
    Corrupt,      // 해시가 맞지 않거나 줄을 읽을 수 없음
    Truncated,    // checkpoint 와 줄 수·마지막 해시가 다름
    BrokenChain,  // 세그먼트 사이 연결이 끊김
};

[[nodiscard]] std::string_view audit_error_name(AuditError error) noexcept;

inline constexpr int schema_version = 1;
inline constexpr std::chrono::days minimum_retention{365};

class AuditLog {
public:
    // dir 이 없으면 만든다. 마지막 세그먼트의 마지막 해시에서 이어 쓴다.
    [[nodiscard]] static std::expected<std::unique_ptr<AuditLog>, AuditError> open(std::filesystem::path dir,
                                                                                  std::chrono::days retention);

    // 줄 하나를 쓴다. v·ts·kind·sev·prev·hash 는 여기서 붙인다. 날짜가 바뀌면 앞 세그먼트를 닫고 만료 삭제를 한다.
    [[nodiscard]] std::expected<void, AuditError> append(std::string_view kind, std::string_view severity,
                                                         nlohmann::json fields, Clock::time_point now = Clock::now());

    // 보존 기간이 지난 세그먼트를 지우고 삭제 이벤트를 남긴다. 지운 세그먼트 수.
    [[nodiscard]] std::expected<int, AuditError> expire(Clock::time_point now = Clock::now());

    [[nodiscard]] const std::filesystem::path& dir() const noexcept { return dir_; }

private:
    struct Key {
        explicit Key() = default;
    };

public:
    // open 만 만든다(Key 는 밖에서 만들 수 없다).
    AuditLog(Key, std::filesystem::path dir, std::chrono::days retention) : dir_(std::move(dir)), retention_(retention) {}

private:
    std::expected<void, AuditError> write_line(std::string_view kind, std::string_view severity, nlohmann::json fields,
                                               Clock::time_point now);
    std::expected<void, AuditError> close_segment();
    std::expected<int, AuditError> expire_locked(Clock::time_point now);

    std::filesystem::path dir_;
    std::chrono::days retention_;
    std::mutex mutex_;
    std::string day_;        // 지금 쓰는 세그먼트 날짜(YYYY-MM-DD)
    std::string last_hash_;  // 마지막으로 쓴 줄의 해시
    std::uint64_t lines_ = 0;  // 지금 세그먼트의 줄 수
};

struct VerifyReport {
    int segments = 0;
    std::uint64_t lines = 0;
};

// 폴더 전체를 검증한다: 줄 해시, 줄 사이 연결, 세그먼트 사이 연결(지운 세그먼트는 삭제 이벤트로), checkpoint.
[[nodiscard]] std::expected<VerifyReport, AuditError> verify(const std::filesystem::path& dir);

}  // namespace prompt_airlock::audit
