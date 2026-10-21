#include "prompt_airlock/audit/log.hpp"

#include <gtest/gtest.h>

#include <fstream>
#include <random>
#include <sstream>
#include <string>
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

}  // namespace
