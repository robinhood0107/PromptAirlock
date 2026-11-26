#include "prompt_airlock/audit/log.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <format>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

namespace audit = prompt_airlock::audit;
namespace fs = std::filesystem;
using namespace std::chrono;

class AuditLogTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = fs::temp_directory_path() / ("pa-audit-" + std::to_string(std::random_device{}()));
        fs::remove_all(dir_);
    }
    void TearDown() override { fs::remove_all(dir_); }

    static audit::Clock::time_point day(int n) { return audit::Clock::time_point{} + days(20000 + n) + hours(9); }

    std::vector<std::string> lines(const std::string& name) {
        std::ifstream in(dir_ / name, std::ios::binary);
        std::vector<std::string> out;
        for (std::string l; std::getline(in, l);) {
            out.push_back(l);
        }
        return out;
    }
    void rewrite(const std::string& name, const std::vector<std::string>& content) {
        std::ofstream out(dir_ / name, std::ios::binary | std::ios::trunc);
        for (const auto& l : content) {
            out << l << '\n';
        }
    }
    std::string name_of(int n) {
        return std::format("audit-{:%F}.jsonl", floor<days>(day(n)));
    }
    std::string name_of(audit::Clock::time_point at) {
        return std::format("audit-{:%F}.jsonl", floor<days>(at));
    }

    fs::path dir_;
};

TEST_F(AuditLogTest, ChainsLinesAcrossDaysAndVerifies) {
    auto log = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE(log.has_value());
    for (int d = 0; d < 3; ++d) {
        for (int i = 0; i < 4; ++i) {
            ASSERT_TRUE((*log)->append("request", "info", {{"n", i}}, day(d)).has_value());
        }
    }
    const auto report = audit::verify(dir_);
    ASSERT_TRUE(report.has_value()) << audit::audit_error_name(report.error());
    EXPECT_EQ(report->segments, 3);
    EXPECT_EQ(report->lines, 12u);
    // 다시 열어도 이어서 쓴다
    log->reset();
    auto again = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE((*again)->append("request", "info", {}, day(2)).has_value());
    EXPECT_EQ(audit::verify(dir_)->lines, 13u);
}

TEST_F(AuditLogTest, DetectsEditDeleteAndTruncation) {
    auto log = audit::AuditLog::open(dir_, days(365));
    for (int d = 0; d < 2; ++d) {
        for (int i = 0; i < 3; ++i) {
            ASSERT_TRUE((*log)->append("request", "info", {{"n", i}}, day(d)).has_value());
        }
    }
    log->reset();
    const std::string first = name_of(0);
    const auto original = lines(first);

    auto edited = original;
    edited[1].replace(edited[1].find("\"n\":1"), 5, "\"n\":9");
    rewrite(first, edited);
    EXPECT_EQ(audit::verify(dir_).error(), audit::AuditError::Corrupt);

    auto removed = original;
    removed.erase(removed.begin() + 1);
    rewrite(first, removed);
    EXPECT_EQ(audit::verify(dir_).error(), audit::AuditError::BrokenChain);

    auto cut = original;
    cut.pop_back();  // 끝 줄을 잘라도 줄 사이 연결은 맞지만 checkpoint 와 다르다
    rewrite(first, cut);
    EXPECT_EQ(audit::verify(dir_).error(), audit::AuditError::Truncated);

    rewrite(first, original);
    EXPECT_TRUE(audit::verify(dir_).has_value());
}

TEST_F(AuditLogTest, TruncatedClosedSegmentFailsCheckpoint) {
    auto log = audit::AuditLog::open(dir_, days(365));
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE((*log)->append("request", "info", {{"n", i}}, day(0)).has_value());
    }
    ASSERT_TRUE((*log)->append("request", "info", {}, day(1)).has_value());
    log->reset();
    // 다음 세그먼트까지 함께 바꿔 연결을 맞춰도 checkpoint 가 끝 절단을 잡는다
    auto first = lines(name_of(0));
    first.pop_back();
    rewrite(name_of(0), first);
    fs::remove(dir_ / name_of(1));
    EXPECT_EQ(audit::verify(dir_).error(), audit::AuditError::Truncated);
}

TEST_F(AuditLogTest, ExpiresWholeSegmentsAndKeepsChainVerifiable) {
    auto log = audit::AuditLog::open(dir_, days(1));  // 365 일보다 짧게 줘도 365 일로 올린다
    ASSERT_TRUE((*log)->append("request", "info", {}, day(0)).has_value());
    ASSERT_TRUE((*log)->append("request", "info", {}, day(1)).has_value());
    ASSERT_TRUE((*log)->append("request", "info", {}, day(300)).has_value());
    EXPECT_TRUE(fs::exists(dir_ / name_of(0)));
    ASSERT_TRUE((*log)->append("request", "info", {}, day(366)).has_value());
    EXPECT_FALSE(fs::exists(dir_ / name_of(0)));
    EXPECT_TRUE(fs::exists(dir_ / name_of(1)));
    const auto report = audit::verify(dir_);
    ASSERT_TRUE(report.has_value()) << audit::audit_error_name(report.error());
    // 삭제 이벤트가 남는다
    bool found = false;
    for (const auto& l : lines(name_of(366))) {
        found = found || l.find("\"kind\":\"expire\"") != std::string::npos;
    }
    EXPECT_TRUE(found);
}

TEST_F(AuditLogTest, ReadRecentFiltersItsTimeWindowAndChecksTheCurrentSegmentState) {
    auto log = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE(log);
    const auto now = audit::Clock::now();
    ASSERT_TRUE((*log)->append("request", "info", {{"n", 1}}, now - hours(25)));
    ASSERT_TRUE((*log)->append("request", "info", {{"n", 2}}, now));

    const auto recent = (*log)->read_recent(now);
    ASSERT_TRUE(recent) << audit::audit_error_name(recent.error());
    ASSERT_EQ(recent->records.size(), 1u);
    EXPECT_EQ(recent->records[0]["n"], 2);
    EXPECT_TRUE(audit::verify(dir_));
}

TEST_F(AuditLogTest, ReadRecentRejectsDeletedAndLineBoundaryTruncatedActiveSegments) {
    auto log = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE(log);
    const auto now = audit::Clock::now();
    ASSERT_TRUE((*log)->append("request", "info", {{"n", 1}}, now));
    ASSERT_TRUE(fs::remove(dir_ / name_of(now)));
    const auto deleted = (*log)->read_recent(now);
    ASSERT_FALSE(deleted);

    log->reset();
    auto again = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE(again);
    ASSERT_TRUE((*again)->append("request", "info", {{"n", 1}}, now));
    ASSERT_TRUE((*again)->append("request", "info", {{"n", 2}}, now));
    const auto original = lines(name_of(now));
    ASSERT_EQ(original.size(), 2u);
    rewrite(name_of(now), {original.front()});
    const auto truncated = (*again)->read_recent(now);
    ASSERT_FALSE(truncated);
    EXPECT_EQ(truncated.error(), audit::AuditError::Truncated);
}

TEST_F(AuditLogTest, ReadRecentReturnsVerifiedNewestSuffixAfterOversizedRecord) {
    auto log = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE(log);
    const auto now = day(1);
    ASSERT_TRUE((*log)->append("egress", "info", {{"sent", std::string(audit::recent_query_max_line_bytes + 1, 'x')}}, day(0)));
    ASSERT_TRUE((*log)->append("request", "info", {{"n", 2}}, now));
    const auto recent = (*log)->read_recent(now);
    ASSERT_TRUE(recent) << audit::audit_error_name(recent.error());
    EXPECT_FALSE(recent->complete);
    ASSERT_EQ(recent->records.size(), 1u);
    EXPECT_EQ(recent->records[0]["n"], 2);
}

TEST_F(AuditLogTest, ReadRecentReturnsVerifiedNewestSuffixWithinByteBudget) {
    auto log = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE(log);
    const auto now = audit::Clock::now();
    const std::string padding(900U << 10, 'x');
    for (int i = 0; i < 19; ++i) {
        ASSERT_TRUE((*log)->append("request", "info", {{"n", i}, {"padding", padding}}, now));
    }

    const auto recent = (*log)->read_recent(now);
    ASSERT_TRUE(recent) << audit::audit_error_name(recent.error());
    EXPECT_FALSE(recent->complete);
    EXPECT_LT(recent->records.size(), 19u);
    ASSERT_FALSE(recent->records.empty());
    EXPECT_EQ(recent->records.back()["n"], 18);
}

TEST_F(AuditLogTest, ReadRecentRejectsDamagedClosedCheckpoint) {
    auto log = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE(log);
    const auto now = day(0) + hours(20);
    ASSERT_TRUE((*log)->append("request", "info", {{"n", 1}}, day(0)));
    ASSERT_TRUE((*log)->append("request", "info", {{"n", 2}}, day(1)));

    const auto checkpoint_path = dir_ / std::format("audit-{:%F}.checkpoint", floor<days>(day(0)));
    std::ifstream input(checkpoint_path, std::ios::binary);
    nlohmann::json checkpoint;
    input >> checkpoint;
    ASSERT_TRUE(input);
    checkpoint["last_hash"] = std::string(64, 'f');
    std::ofstream output(checkpoint_path, std::ios::binary | std::ios::trunc);
    output << checkpoint.dump() << '\n';
    output.close();

    const auto recent = (*log)->read_recent(now);
    ASSERT_FALSE(recent);
    EXPECT_EQ(recent.error(), audit::AuditError::Truncated);
}

TEST_F(AuditLogTest, RecentReadsSerializeWithConcurrentAppendAndExpire) {
    auto log = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE(log);
    const auto now = audit::Clock::now();
    ASSERT_TRUE((*log)->append("start", "info", {}, now));
    std::atomic<bool> failed{false};
    std::thread writer([&] {
        for (int i = 0; i < 80; ++i) {
            if (!(*log)->append("request", "info", {{"n", i}}, now)) failed = true;
        }
    });
    std::thread reader([&] {
        for (int i = 0; i < 80; ++i) {
            if (!(*log)->read_recent(now)) failed = true;
        }
    });
    std::thread expirer([&] {
        for (int i = 0; i < 8; ++i) {
            if (!(*log)->expire(now)) failed = true;
        }
    });
    writer.join();
    reader.join();
    expirer.join();
    EXPECT_FALSE(failed);
    EXPECT_TRUE(audit::verify(dir_));
}

TEST_F(AuditLogTest, RecentReadKeepsOldRecordsOutOfItsFixedWindow) {
    auto log = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE(log);
    const auto now = audit::Clock::now();
    ASSERT_TRUE((*log)->append("request", "info", {{"n", 1}}, now - hours(25)));
    ASSERT_TRUE((*log)->append("request", "info", {{"n", 2}}, now));
    const auto recent = (*log)->read_recent(now);
    ASSERT_TRUE(recent);
    ASSERT_EQ(recent->records.size(), 1u);
    EXPECT_EQ(recent->records[0]["n"], 2);
}

TEST_F(AuditLogTest, StatsCountsOnlyFinalRequestsAndLeavesFilesUnchanged) {
    auto log = audit::AuditLog::open(dir_, days(365));
    ASSERT_TRUE(log);
    const auto now = audit::Clock::now();
    ASSERT_TRUE((*log)->append("start", "info", {}, now));
    ASSERT_TRUE((*log)->append("request", "info", {{"result", "pass"}, {"status", 200U}}, now));
    ASSERT_TRUE((*log)->append("egress", "info", {{"sent", "SYNTHETIC_EGRESS_BODY"}}, now));
    ASSERT_TRUE((*log)->append("request", "warn", {{"result", "reject"}, {"reason", "grade_sensitive"}}, now));
    ASSERT_TRUE((*log)->append("request", "warn", {{"result", "reject"}, {"reason", "entity_blocked"}, {"status", 400U}}, now));
    ASSERT_TRUE((*log)->append("confirmation", "info", {{"result", "checked"}}, now));
    ASSERT_TRUE((*log)->append("request", "warn", {{"result", "reject"}, {"reason", "confirmation_required"}, {"status", 409U}}, now));
    ASSERT_TRUE((*log)->append("egress_answer", "info", {{"answer", "SYNTHETIC_RESPONSE"}}, now));
    ASSERT_TRUE((*log)->append("request", "warn", {{"result", "reject"}, {"reason", "provider_error"}, {"status", 502U}}, now));
    ASSERT_TRUE((*log)->append("preview", "info", {{"result", "pass"}, {"status", 200U}}, now));
    log->reset();

    const auto path = dir_ / name_of(now);
    const auto before = lines(name_of(now));
    const auto modified_before = fs::last_write_time(path);
    const auto stats = audit::AuditLog::stats_recent_readonly(dir_, now);
    ASSERT_TRUE(stats.has_value()) << audit::audit_error_name(stats.error().error);
    EXPECT_EQ(stats->state, audit::StatsState::Ready);
    EXPECT_TRUE(stats->complete);
    EXPECT_EQ(stats->records, 10U);
    EXPECT_EQ(stats->requests, 5U);
    EXPECT_EQ(stats->normal, 1U);
    EXPECT_EQ(stats->blocked, 2U);
    EXPECT_EQ(stats->confirmation, 1U);
    EXPECT_EQ(stats->failure, 1U);
    EXPECT_EQ(lines(name_of(now)), before);
    EXPECT_EQ(fs::last_write_time(path), modified_before);
    EXPECT_FALSE(fs::exists(dir_ / "admin"));
}

TEST_F(AuditLogTest, StatsDistinguishesMissingAndEmptyDirectories) {
    ASSERT_TRUE(fs::create_directory(dir_));
    const auto missing = dir_ / "missing";
    const auto absent = audit::AuditLog::stats_recent_readonly(missing);
    ASSERT_TRUE(absent.has_value());
    EXPECT_EQ(absent->state, audit::StatsState::Missing);
    EXPECT_FALSE(fs::exists(missing));

    const auto empty = dir_ / "empty";
    ASSERT_TRUE(fs::create_directory(empty));
    const auto no_records = audit::AuditLog::stats_recent_readonly(empty);
    ASSERT_TRUE(no_records.has_value());
    EXPECT_EQ(no_records->state, audit::StatsState::Empty);
    EXPECT_EQ(no_records->records, 0U);
    EXPECT_EQ(no_records->requests, 0U);
    EXPECT_TRUE(fs::is_empty(empty));
}

TEST_F(AuditLogTest, StatsRejectsPartialCorruptAndMalformedRequestRecords) {
    const auto partial_dir = dir_ / "partial";
    auto partial_log = audit::AuditLog::open(partial_dir, days(365));
    ASSERT_TRUE(partial_log);
    const auto now = day(1);
    ASSERT_TRUE((*partial_log)->append(
        "egress", "info", {{"sent", std::string(audit::recent_query_max_line_bytes + 1, 'x')}}, day(0)));
    ASSERT_TRUE((*partial_log)->append("request", "info", {{"result", "pass"}, {"status", 200U}}, now));
    partial_log->reset();
    const auto partial = audit::AuditLog::stats_recent_readonly(partial_dir, now);
    ASSERT_TRUE(partial.has_value());
    EXPECT_EQ(partial->state, audit::StatsState::Partial);
    EXPECT_FALSE(partial->complete);
    EXPECT_EQ(partial->requests, 0U);
    EXPECT_EQ(partial->normal, 0U);

    const auto corrupt_dir = dir_ / "corrupt";
    auto corrupt_log = audit::AuditLog::open(corrupt_dir, days(365));
    ASSERT_TRUE(corrupt_log);
    ASSERT_TRUE((*corrupt_log)->append("request", "info", {{"result", "pass"}, {"status", 200U}}, now));
    corrupt_log->reset();
    const auto corrupt_path = corrupt_dir / std::format("audit-{:%F}.jsonl", floor<days>(now));
    std::ifstream input(corrupt_path, std::ios::binary);
    std::string line;
    ASSERT_TRUE(std::getline(input, line));
    const auto pass = line.find("\"result\":\"pass\"");
    ASSERT_NE(pass, std::string::npos);
    line.replace(pass, std::string("\"result\":\"pass\"").size(), "\"result\":\"reject\"");
    std::ofstream output(corrupt_path, std::ios::binary | std::ios::trunc);
    output << line << '\n';
    output.close();
    const auto corrupt = audit::AuditLog::stats_recent_readonly(corrupt_dir, now);
    ASSERT_FALSE(corrupt.has_value());
    EXPECT_EQ(corrupt.error().stage, audit::StatsStage::Verify);
    EXPECT_EQ(corrupt.error().error, audit::AuditError::Corrupt);

    const auto fields_dir = dir_ / "fields";
    auto fields_log = audit::AuditLog::open(fields_dir, days(365));
    ASSERT_TRUE(fields_log);
    ASSERT_TRUE((*fields_log)->append("request", "info", {{"result", "pass"}}, now));
    fields_log->reset();
    const auto invalid_fields = audit::AuditLog::stats_recent_readonly(fields_dir, now);
    ASSERT_FALSE(invalid_fields.has_value());
    EXPECT_EQ(invalid_fields.error().stage, audit::StatsStage::Fields);
    EXPECT_EQ(invalid_fields.error().error, audit::AuditError::Corrupt);
}

}  // namespace
