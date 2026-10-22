#include "prompt_airlock/audit/log.hpp"

#include <algorithm>
#include <format>
#include <fstream>
#include <set>
#include <span>
#include <vector>

#include "prompt_airlock/core/sha256.hpp"

namespace prompt_airlock::audit {
namespace {

using json = nlohmann::json;
namespace fs = std::filesystem;

const std::string genesis(64, '0');
constexpr std::string_view prefix = "audit-";

std::string day_of(Clock::time_point t) {
    return std::format("{:%F}", std::chrono::floor<std::chrono::days>(t));
}

std::string stamp(Clock::time_point t) {
    return std::format("{:%FT%TZ}", std::chrono::floor<std::chrono::milliseconds>(t));
}

fs::path segment_path(const fs::path& dir, std::string_view day) { return dir / std::format("{}{}.jsonl", prefix, day); }
fs::path checkpoint_path(const fs::path& dir, std::string_view day) {
    return dir / std::format("{}{}.checkpoint", prefix, day);
}

std::string hash_of(std::string_view text) { return core::sha256_hex(std::as_bytes(std::span(text.data(), text.size()))); }

// 폴더의 세그먼트 날짜를 오래된 순으로.
std::vector<std::string> segment_days(const fs::path& dir) {
    std::vector<std::string> days;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        const std::string name = entry.path().filename().string();
        if (name.starts_with(prefix) && name.ends_with(".jsonl") && name.size() == prefix.size() + 10 + 6) {
            days.push_back(name.substr(prefix.size(), 10));
        }
    }
    std::ranges::sort(days);
    return days;
}

struct Line {
    json record;
    std::string hash;
};

// 줄 하나를 읽고 해시를 확인한다. 해시는 hash 를 뺀 객체의 직렬화(키 정렬)로 계산한다.
std::expected<Line, AuditError> parse_line(std::string_view text) {
    json record = json::parse(text, nullptr, /*allow_exceptions=*/false);
    if (!record.is_object() || !record.contains("hash") || !record["hash"].is_string() || !record.contains("prev")) {
        return std::unexpected(AuditError::Corrupt);
    }
    std::string hash = record["hash"];
    record.erase("hash");
    if (hash_of(record.dump()) != hash) {
        return std::unexpected(AuditError::Corrupt);
    }
    return Line{std::move(record), std::move(hash)};
}

}  // namespace

std::string_view audit_error_name(AuditError error) noexcept {
    switch (error) {
        case AuditError::Io: return "io";
        case AuditError::Corrupt: return "corrupt";
        case AuditError::Truncated: return "truncated";
        case AuditError::BrokenChain: return "broken_chain";
    }
    return "unknown";
}

std::expected<std::unique_ptr<AuditLog>, AuditError> AuditLog::open(fs::path dir, std::chrono::days retention) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec || !fs::is_directory(dir)) {
        return std::unexpected(AuditError::Io);
    }
    auto log = std::make_unique<AuditLog>(Key{}, std::move(dir), std::max(retention, minimum_retention));
    log->last_hash_ = genesis;
    const auto days = segment_days(log->dir_);
    if (!days.empty()) {
        // 마지막 세그먼트의 마지막 줄에서 이어 쓴다
        std::ifstream in(segment_path(log->dir_, days.back()), std::ios::binary);
        std::string text;
        std::string last;
        std::uint64_t count = 0;
        while (std::getline(in, text)) {
            if (!text.empty()) {
                last = text;
                ++count;
            }
        }
        if (!last.empty()) {
            auto line = parse_line(last);
            if (!line) {
                return std::unexpected(line.error());
            }
            log->last_hash_ = line->hash;
        }
        if (!fs::exists(checkpoint_path(log->dir_, days.back()))) {
            log->day_ = days.back();
            log->lines_ = count;
        }
    }
    return log;
}

std::expected<void, AuditError> AuditLog::append(std::string_view kind, std::string_view severity, json fields,
                                                 Clock::time_point now) {
    std::scoped_lock lock(mutex_);
    const std::string today = day_of(now);
    if (today != day_) {
        if (!day_.empty()) {
            if (auto closed = close_segment(); !closed) {
                return closed;
            }
        }
        day_ = today;
        lines_ = 0;
        if (auto expired = expire_locked(now); !expired) {
            return std::unexpected(expired.error());
        }
    }
    return write_line(kind, severity, std::move(fields), now);
}

std::expected<int, AuditError> AuditLog::expire(Clock::time_point now) {
    std::scoped_lock lock(mutex_);
    if (day_.empty()) {
        day_ = day_of(now);
        lines_ = 0;
    }
    return expire_locked(now);
}

std::expected<void, AuditError> AuditLog::write_line(std::string_view kind, std::string_view severity, json fields,
                                                     Clock::time_point now) {
    json record = fields.is_object() ? std::move(fields) : json::object();
    record["v"] = schema_version;
    record["ts"] = stamp(now);
    record["kind"] = kind;
    record["sev"] = severity;
    record["prev"] = last_hash_;
    const std::string hash = hash_of(record.dump());
    record["hash"] = hash;
    std::ofstream out(segment_path(dir_, day_), std::ios::binary | std::ios::app);
    out << record.dump() << '\n';
    out.flush();
    if (!out) {
        return std::unexpected(AuditError::Io);
    }
    last_hash_ = hash;
    ++lines_;
    return {};
}

std::expected<void, AuditError> AuditLog::close_segment() {
    std::ofstream out(checkpoint_path(dir_, day_), std::ios::binary | std::ios::trunc);
    out << json{{"last_hash", last_hash_}, {"lines", lines_}}.dump() << '\n';
    out.flush();
    return out ? std::expected<void, AuditError>{} : std::unexpected(AuditError::Io);
}

std::expected<int, AuditError> AuditLog::expire_locked(Clock::time_point now) {
    const std::string oldest_kept = day_of(now - retention_);
    int removed = 0;
    for (const auto& day : segment_days(dir_)) {
        if (day >= oldest_kept || day == day_) {
            continue;
        }
        // 지울 세그먼트의 마지막 해시를 남겨, 남은 세그먼트의 연결을 계속 검증할 수 있게 한다
        std::ifstream in(segment_path(dir_, day), std::ios::binary);
        std::string text;
        std::string last;
        while (std::getline(in, text)) {
            if (!text.empty()) {
                last = text;
            }
        }
        in.close();
        std::error_code ec;
        if (last.empty()) {  // 빈 세그먼트는 연결에 들어 있지 않으므로 그냥 지운다
            fs::remove(segment_path(dir_, day), ec);
            fs::remove(checkpoint_path(dir_, day), ec);
            continue;
        }
        auto line = parse_line(last);
        if (!line) {
            return std::unexpected(line.error());
        }
        fs::remove(segment_path(dir_, day), ec);
        fs::remove(checkpoint_path(dir_, day), ec);
        if (auto logged = write_line("expire", "info", {{"segment", day}, {"last_hash", line->hash}}, now); !logged) {
            return std::unexpected(logged.error());
        }
        ++removed;
    }
    return removed;
}

std::expected<VerifyReport, AuditError> verify(const fs::path& dir) {
    VerifyReport report;
    const auto days = segment_days(dir);
    // 지운 세그먼트의 마지막 해시(삭제 이벤트)는 남은 첫 세그먼트의 시작점으로 인정한다
    std::set<std::string> expired_ends;
    std::vector<std::vector<Line>> segments;
    for (const auto& day : days) {
        std::ifstream in(segment_path(dir, day), std::ios::binary);
        if (!in) {
            return std::unexpected(AuditError::Io);
        }
        std::vector<Line> lines;
        std::string text;
        while (std::getline(in, text)) {
            if (text.empty()) {
                continue;
            }
            auto line = parse_line(text);
            if (!line) {
                return std::unexpected(line.error());
            }
            if (line->record.value("kind", "") == "expire") {
                expired_ends.insert(line->record.value("last_hash", ""));
            }
            lines.push_back(std::move(*line));
        }
        segments.push_back(std::move(lines));
    }
    std::string prev;
    for (std::size_t i = 0; i < segments.size(); ++i) {
        const auto& lines = segments[i];
        for (std::size_t j = 0; j < lines.size(); ++j) {
            const std::string link = lines[j].record["prev"];
            const bool first = i == 0 && j == 0;
            const bool ok = first ? (link == genesis || expired_ends.contains(link)) : link == prev;
            if (!ok) {
                return std::unexpected(AuditError::BrokenChain);
            }
            prev = lines[j].hash;
            ++report.lines;
        }
        const auto checkpoint = checkpoint_path(dir, days[i]);
        if (fs::exists(checkpoint)) {
            std::ifstream in(checkpoint, std::ios::binary);
            std::string text;
            std::getline(in, text);
            const json cp = json::parse(text, nullptr, false);
            const std::string last = lines.empty() ? std::string() : lines.back().hash;
            if (!cp.is_object() || cp.value("lines", std::uint64_t{0}) != lines.size() || cp.value("last_hash", "") != last) {
                return std::unexpected(AuditError::Truncated);
            }
        } else if (i + 1 < segments.size()) {
            return std::unexpected(AuditError::Truncated);  // 마지막이 아닌 세그먼트는 닫혀 있어야 한다
        }
        ++report.segments;
    }
    return report;
}

}  // namespace prompt_airlock::audit
