#include "prompt_airlock/audit/log.hpp"

#include <algorithm>
#include <format>
#include <fstream>
#include <limits>
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

struct SegmentSnapshot {
    std::string day;
    fs::path path;
    std::uintmax_t size = 0;
    std::optional<std::pair<fs::path, std::uintmax_t>> checkpoint;
};

std::expected<std::string, AuditError> read_snapshot(const fs::path& path, std::uintmax_t size, std::size_t limit) {
    if (size > limit || size > static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max())) {
        return std::unexpected(AuditError::TooLarge);
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::unexpected(AuditError::Io);
    std::string data(static_cast<std::size_t>(size), '\0');
    if (data.empty()) return std::unexpected(AuditError::Corrupt);
    in.read(data.data(), static_cast<std::streamsize>(data.size()));
    if (in.gcount() != static_cast<std::streamsize>(data.size())) return std::unexpected(AuditError::Corrupt);
    if (data.back() != '\n') return std::unexpected(AuditError::Corrupt);
    return data;
}

std::expected<std::string, AuditError> read_tail_line(const fs::path& path, std::uint64_t file_bytes,
                                                     std::size_t line_bytes) {
    if (line_bytes == 0 || line_bytes > recent_query_max_bytes || file_bytes < line_bytes ||
        file_bytes > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        return std::unexpected(AuditError::TooLarge);
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::unexpected(AuditError::Io);
    in.seekg(static_cast<std::streamoff>(file_bytes - line_bytes));
    std::string line(line_bytes, '\0');
    in.read(line.data(), static_cast<std::streamsize>(line.size()));
    if (in.gcount() != static_cast<std::streamsize>(line.size())) return std::unexpected(AuditError::Corrupt);
    if (line.back() != '\n' || line.find('\n') != line.size() - 1) return std::unexpected(AuditError::Corrupt);
    line.pop_back();
    return line;
}

bool valid_stamp(std::string_view value) {
    if (value.size() != 24 || value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' ||
        value[16] != ':' || value[19] != '.' || value[23] != 'Z') {
        return false;
    }
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16 || i == 19 || i == 23) continue;
        if (value[i] < '0' || value[i] > '9') return false;
    }
    return true;
}

bool valid_link(std::string_view value) {
    return value.size() == 64 && std::ranges::all_of(value, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

bool valid_record(const Line& line, std::string_view day) {
    const auto& record = line.record;
    if (!record.contains("v") || !record["v"].is_number_integer() || record["v"].get<int>() != schema_version ||
        !record.contains("ts") || !record["ts"].is_string() || !record.contains("kind") ||
        !record["kind"].is_string() || !record.contains("sev") || !record["sev"].is_string() ||
        !record.contains("prev") || !record["prev"].is_string()) {
        return false;
    }
    const auto& timestamp = record["ts"].get_ref<const std::string&>();
    const auto& link = record["prev"].get_ref<const std::string&>();
    return valid_stamp(timestamp) && timestamp.substr(0, 10) == day && valid_link(link);
}

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
        case AuditError::TooLarge: return "too_large";
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
        const auto path = segment_path(log->dir_, days.back());
        std::ifstream in(path, std::ios::binary);
        std::string text;
        std::string last;
        std::uint64_t count = 0;
        while (std::getline(in, text)) {
            if (in.eof() || text.empty()) return std::unexpected(AuditError::Corrupt);
            last = text;
            ++count;
            log->bytes_ += text.size() + 1;
            log->last_line_bytes_ = text.size() + 1;
        }
        if (in.bad()) return std::unexpected(AuditError::Io);
        std::error_code size_error;
        if (fs::file_size(path, size_error) != log->bytes_ || size_error) {
            return std::unexpected(size_error ? AuditError::Io : AuditError::Truncated);
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
        bytes_ = 0;
        last_line_bytes_ = 0;
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
        bytes_ = 0;
        last_line_bytes_ = 0;
    }
    return expire_locked(now);
}

std::expected<std::vector<json>, AuditError> AuditLog::read_recent(Clock::time_point now) {
    struct ActiveSnapshot {
        std::string day;
        std::string last_hash;
        std::uint64_t lines = 0;
        std::uint64_t bytes = 0;
        std::size_t last_line_bytes = 0;
        fs::path path;
    } active;
    std::vector<SegmentSnapshot> snapshots;
    std::size_t total_bytes = 0;
    {
        std::scoped_lock lock(mutex_);
        active = {day_, last_hash_, lines_, bytes_, last_line_bytes_, {}};
        if (!active.day.empty()) {
            if ((active.lines == 0) != (active.bytes == 0) ||
                (active.lines == 0) != (active.last_line_bytes == 0)) {
                return std::unexpected(AuditError::Truncated);
            }
            if (active.lines != 0) {
                active.path = segment_path(dir_, active.day);
                std::error_code ec;
                const auto actual_bytes = fs::file_size(active.path, ec);
                if (ec) return std::unexpected(AuditError::Io);
                if (actual_bytes != active.bytes) return std::unexpected(AuditError::Truncated);
            }
        }
        for (int offset = static_cast<int>(recent_query_lookback_days); offset >= 0; --offset) {
            const std::string day = day_of(now - std::chrono::days(offset));
            const auto path = segment_path(dir_, day);
            std::error_code ec;
            if (!fs::exists(path, ec)) {
                if (ec) return std::unexpected(AuditError::Io);
                continue;
            }
            const auto size = fs::file_size(path, ec);
            if (ec) return std::unexpected(AuditError::Io);
            if (size > recent_query_max_bytes - total_bytes) return std::unexpected(AuditError::TooLarge);
            total_bytes += static_cast<std::size_t>(size);

            std::optional<std::pair<fs::path, std::uintmax_t>> checkpoint;
            const auto cp_path = checkpoint_path(dir_, day);
            const bool has_checkpoint = fs::exists(cp_path, ec);
            if (ec) return std::unexpected(AuditError::Io);
            if (has_checkpoint) {
                const auto checkpoint_size = fs::file_size(cp_path, ec);
                if (ec) return std::unexpected(AuditError::Io);
                if (checkpoint_size > 256) return std::unexpected(AuditError::Truncated);
                if (checkpoint_size > recent_query_max_bytes - total_bytes) return std::unexpected(AuditError::TooLarge);
                total_bytes += static_cast<std::size_t>(checkpoint_size);
                checkpoint.emplace(cp_path, checkpoint_size);
            }
            snapshots.push_back({day, path, size, std::move(checkpoint)});
        }
    }

    if (active.lines != 0) {
        auto tail = read_tail_line(active.path, active.bytes, active.last_line_bytes);
        if (!tail) {
            return std::unexpected(tail.error() == AuditError::TooLarge ? AuditError::Corrupt : tail.error());
        }
        auto last = parse_line(*tail);
        if (!last) return std::unexpected(last.error());
        if (last->hash != active.last_hash || !valid_record(*last, active.day)) {
            return std::unexpected(AuditError::Corrupt);
        }
    }

    std::vector<json> recent;
    std::optional<std::string> previous_hash;
    std::size_t total_lines = 0;
    const std::string earliest = stamp(now - recent_query_window);
    const std::string latest = stamp(now);
    for (std::size_t i = 0; i < snapshots.size(); ++i) {
        const auto& snapshot = snapshots[i];
        auto data = read_snapshot(snapshot.path, snapshot.size, recent_query_max_bytes);
        if (!data) return std::unexpected(data.error());
        std::optional<std::string> checkpoint_text;
        if (snapshot.checkpoint) {
            auto contents = read_snapshot(snapshot.checkpoint->first, snapshot.checkpoint->second, 256);
            if (!contents) {
                return std::unexpected(contents.error() == AuditError::TooLarge ? AuditError::Truncated : contents.error());
            }
            checkpoint_text.emplace(std::move(*contents));
        }
        std::vector<Line> lines;
        std::size_t start = 0;
        while (start < data->size()) {
            const auto end = data->find('\n', start);
            if (end == std::string::npos || end == start) return std::unexpected(AuditError::Corrupt);
            const std::string_view text(data->data() + start, end - start);
            if (text.size() > recent_query_max_line_bytes) return std::unexpected(AuditError::TooLarge);
            auto line = parse_line(text);
            if (!line) return std::unexpected(line.error());
            const auto& record = line->record;
            if (!valid_record(*line, snapshot.day)) return std::unexpected(AuditError::Corrupt);
            const auto& link = record["prev"].get_ref<const std::string&>();
            if (previous_hash && link != *previous_hash) return std::unexpected(AuditError::BrokenChain);
            previous_hash = line->hash;
            lines.push_back(std::move(*line));
            ++total_lines;
            if (total_lines > recent_query_max_lines) return std::unexpected(AuditError::TooLarge);
            start = end + 1;
        }
        if (lines.empty()) return std::unexpected(AuditError::Corrupt);

        if (checkpoint_text) {
            const std::string_view cp_text(*checkpoint_text);
            const auto cp_end = cp_text.find('\n');
            if (cp_end == std::string_view::npos || cp_end + 1 != cp_text.size()) return std::unexpected(AuditError::Truncated);
            const json checkpoint = json::parse(cp_text.substr(0, cp_end), nullptr, false);
            if (!checkpoint.is_object() || checkpoint.size() != 2 || !checkpoint.contains("lines") ||
                !checkpoint["lines"].is_number_unsigned() || !checkpoint.contains("last_hash") ||
                !checkpoint["last_hash"].is_string() ||
                checkpoint["lines"].get<std::uint64_t>() != lines.size() ||
                checkpoint["last_hash"].get_ref<const std::string&>() != lines.back().hash) {
                return std::unexpected(AuditError::Truncated);
            }
        } else if (i + 1 < snapshots.size()) {
            return std::unexpected(AuditError::Truncated);
        }

        if (snapshot.day == active.day && active.lines != 0 &&
            (data->size() != active.bytes || lines.size() != active.lines || lines.back().hash != active.last_hash)) {
            return std::unexpected(AuditError::Truncated);
        }

        for (auto& line : lines) {
            const auto& timestamp = line.record["ts"].get_ref<const std::string&>();
            if (timestamp >= earliest && timestamp <= latest) recent.push_back(std::move(line.record));
        }
    }
    return recent;
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
    const std::string text = record.dump();
    if (text.size() + 1 > std::numeric_limits<std::uint64_t>::max() - bytes_) {
        return std::unexpected(AuditError::TooLarge);
    }
    std::ofstream out(segment_path(dir_, day_), std::ios::binary | std::ios::app);
    out << text << '\n';
    out.flush();
    if (!out) {
        return std::unexpected(AuditError::Io);
    }
    last_hash_ = hash;
    ++lines_;
    bytes_ += text.size() + 1;
    last_line_bytes_ = text.size() + 1;
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
