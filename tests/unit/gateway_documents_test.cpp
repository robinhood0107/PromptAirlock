#include "prompt_airlock/gateway/documents.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <stop_token>

#include "document_writer.hpp"
#include "prompt_airlock/detect/detectors.hpp"

namespace {
namespace gw = prompt_airlock::gateway;
namespace core = prompt_airlock::core;
namespace ex = prompt_airlock::extract;
namespace doc = pa_test::documents;
using json = nlohmann::json;

gw::ParsedRequest request(std::string_view bytes, std::string_view filename = "a.txt") {
    const json body = {{"messages", json::array({{{"role", "user"}, {"content", json::array({
        {{"type", "file"}, {"file", {{"filename", filename},
            {"file_data", "data:application/octet-stream;base64," + doc::base64(bytes)}}}}
    })}}})}};
    auto parsed = gw::parse_request(body.dump());
    if (!parsed) throw std::runtime_error("invalid test fixture");
    return std::move(*parsed);
}

TEST(GatewayDocuments, JoinsWholeFlowAndMapsEveryOriginalBlock) {
    const std::string content = "앞 문단\n중간 문단\n끝 문단";
    auto parsed = request(content);
    std::vector<gw::FileStatistics> stats;
    auto resolved = gw::resolve_documents(parsed, PA_EXTRACT_EXE, stats, {});
    ASSERT_TRUE(resolved);
    ASSERT_EQ(resolved->document.segments().size(), 1U);
    EXPECT_EQ(resolved->document.segments()[0].text(), content);
    ASSERT_EQ(resolved->locations.size(), 3U);
    const std::string_view expected[] = {"앞 문단", "중간 문단", "끝 문단"};
    for (std::size_t i = 0; i < resolved->locations.size(); ++i) {
        const auto& location = resolved->locations[i];
        EXPECT_EQ(location.file, 0U);
        EXPECT_EQ(location.document, 0U);
        EXPECT_EQ(location.segment.value(), 0U);
        EXPECT_EQ(location.where.view(), "line" + std::to_string(i + 1));
        EXPECT_EQ(resolved->document.segments()[0].text().substr(location.span.begin().value(), location.span.size()),
                  expected[i]);
    }
    ASSERT_EQ(stats.size(), 1U);
    EXPECT_EQ(stats[0].bytes, content.size());
    EXPECT_EQ(stats[0].characters, 13U);  // 추출된 덩어리의 글자 수이며 조립 구분자는 제외한다.
    EXPECT_TRUE(parsed.files[0].bytes.empty());
}

TEST(GatewayDocuments, LargerThan64KiBIsNotTruncatedOrRejectedByTextBudget) {
    const std::string content = "앞\n" + std::string(70000, 'x') + "\n끝";
    auto parsed = request(content);
    std::vector<gw::FileStatistics> stats;
    auto resolved = gw::resolve_documents(parsed, PA_EXTRACT_EXE, stats, {});
    ASSERT_TRUE(resolved);
    EXPECT_EQ(resolved->document.kind(), core::DocumentKind::ExtractedFiles);
    EXPECT_EQ(resolved->document.segments()[0].text(), content);
    EXPECT_EQ(resolved->locations.size(), 3U);
}

TEST(GatewayDocuments, ArchiveDocumentsNeverBecomeOneDetectionSegment) {
    auto parsed = request(doc::make_zip({{"a.txt", "주민번호:900101"}, {"b.txt", "1234567"}}), "a.zip");
    std::vector<gw::FileStatistics> stats;
    auto resolved = gw::resolve_documents(parsed, PA_EXTRACT_EXE, stats, {});
    ASSERT_TRUE(resolved);
    ASSERT_EQ(resolved->document.segments().size(), 2U);
    EXPECT_EQ(resolved->document.segments()[0].text(), "주민번호:900101");
    EXPECT_EQ(resolved->document.segments()[1].text(), "1234567");
    EXPECT_NE(resolved->locations[0].document, resolved->locations[1].document);
    auto detectors = prompt_airlock::detect::Detectors::make({});
    ASSERT_TRUE(detectors);
    const auto found = detectors->detect(resolved->document);
    ASSERT_TRUE(found);
    EXPECT_TRUE(found->entities.empty());
}

TEST(GatewayDocuments, CancellationAndMissingExecutableReturnTypedFailures) {
    auto parsed = request("일반 안내");
    std::vector<gw::FileStatistics> stats;
    std::stop_source stop;
    stop.request_stop();
    auto cancelled = gw::resolve_documents(parsed, PA_EXTRACT_EXE, stats, stop.get_token());
    ASSERT_FALSE(cancelled);
    EXPECT_EQ(std::get<ex::RunError>(cancelled.error()), ex::RunError::Cancelled);
    EXPECT_TRUE(stats.empty());
    auto missing = gw::resolve_documents(parsed, "missing-document-extractor-do-not-create", stats, {});
    ASSERT_FALSE(missing);
    EXPECT_EQ(std::get<ex::RunError>(missing.error()), ex::RunError::StartFailed);
}

TEST(GatewayDocuments, OldAndAmbiguousChildProtocolsAreRejected) {
    const auto extracted = ex::extract(std::as_bytes(std::span(std::string_view("hello"))), "txt");
    ASSERT_TRUE(extracted);
    const auto valid = ex::to_json(extracted);
    auto version = json::parse(valid);
    version["v"] = 1;
    EXPECT_FALSE(ex::from_json(version.dump()));
    auto index = json::parse(valid);
    index["blocks"][0]["document"] = 99;
    EXPECT_FALSE(ex::from_json(index.dump()));
    const auto duplicate = valid.substr(0, valid.size() - 1) + R"(,"v":2})";
    EXPECT_FALSE(ex::from_json(duplicate));
}

}  // namespace
TEST(GatewayDocuments, QuotedCsvKeepsLineBreaksInsideOneCell) {
    auto parsed = request("번호,\"900101\n1234567\"\n", "a.csv");
    std::vector<gw::FileStatistics> stats;
    auto resolved = gw::resolve_documents(parsed, PA_EXTRACT_EXE, stats, {});
    ASSERT_TRUE(resolved);
    EXPECT_EQ(resolved->document.segments()[0].text(), "번호\n|\n900101\n1234567");
    EXPECT_EQ(resolved->locations.size(), 2U);
}
TEST(GatewayDocuments, ExtractedBudgetIsSharedAndSecondFileCannotBypassIt) {
    const std::string text((4U << 20) + 1, 'x');
    const auto encoded = "data:text/plain;base64," + doc::base64(text);
    const json part = {{"type", "file"}, {"file", {{"filename", "input.txt"}, {"file_data", encoded}}}};
    const json body = {{"messages", json::array({{{"role", "user"}, {"content", json::array({part, part})}}})}};
    auto parsed = gw::parse_request(body.dump());
    ASSERT_TRUE(parsed);
    std::vector<gw::FileStatistics> stats;
    auto result = gw::resolve_documents(*parsed, PA_EXTRACT_EXE, stats, {});
    ASSERT_FALSE(result);
    EXPECT_EQ(std::get<ex::ExtractError>(result.error()), ex::ExtractError::TooLarge);
    EXPECT_EQ(stats.size(), 2U);
}
