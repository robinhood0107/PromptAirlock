#include "prompt_airlock/gateway/config.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <string>

namespace {

namespace gw = prompt_airlock::gateway;
using gw::ConfigProblem;
using json = nlohmann::json;

const std::string hash_a(64, 'a');
const std::string hash_b(64, 'b');

json valid() {
    return {
        {"listen", {{"address", "127.0.0.1"}, {"port", 8443}, {"certificate_chain", "certs/server.pem"},
                    {"private_key", "certs/server.key"}}},
        {"provider", {{"url", "https://127.0.0.1:9443/v1/chat/completions"},
                      {"credential_file", "secrets/provider.key"},
                      {"trust_file", "certs/mock-ca.pem"},
                      {"model", "demo-model"}}},
        {"origins", json::array({{{"name", "dept-a"}, {"token_sha256", hash_a}, {"grade_policy", "o-only"}},
                                 {{"name", "dept-b"}, {"token_sha256", hash_b}, {"grade_policy", "declare"}}})},
        {"internal_terms", json::array({"한빛시청", "한빛데이터"})},
        {"output_token_cap", 2048},
    };
}

std::expected<gw::Config, gw::ConfigError> parse(const json& j) { return gw::parse_config(j.dump(), "/etc/airlock"); }

void expect_error(const json& j, ConfigProblem problem, const std::string& field) {
    const auto config = parse(j);
    ASSERT_FALSE(config.has_value()) << field;
    EXPECT_EQ(config.error().problem, problem) << field;
    EXPECT_EQ(config.error().field, field);
}

TEST(GatewayConfig, ReadsValidConfig) {
    const auto config = parse(valid());
    ASSERT_TRUE(config.has_value());
    EXPECT_EQ(config->listen.address, "127.0.0.1");
    EXPECT_EQ(config->listen.port, 8443);
    EXPECT_EQ(config->listen.certificate_chain, std::filesystem::path("/etc/airlock") / "certs/server.pem");
    EXPECT_EQ(config->provider.host, "127.0.0.1");
    EXPECT_EQ(config->provider.port, 9443);
    EXPECT_EQ(config->provider.target, "/v1/chat/completions");
    EXPECT_EQ(config->provider.model, "demo-model");
    ASSERT_EQ(config->origins.size(), 2u);
    EXPECT_EQ(config->origins[0].grade_policy, prompt_airlock::core::GradePolicy::OOnly);
    EXPECT_EQ(config->origins[1].grade_policy, prompt_airlock::core::GradePolicy::Declare);
    EXPECT_EQ(config->internal_terms.size(), 2u);
    EXPECT_EQ(config->output_token_cap.value(), 2048u);
}

TEST(GatewayConfig, OptionalFieldsTakeDefaults) {
    json j = valid();
    j.erase("output_token_cap");
    j["provider"].erase("trust_file");
    j["provider"]["url"] = "https://llm.example.org/v1/chat/completions";
    const auto config = parse(j);
    ASSERT_TRUE(config.has_value());
    EXPECT_EQ(config->output_token_cap.value(), 4096u);
    EXPECT_TRUE(config->provider.trust_file.empty());
    EXPECT_EQ(config->provider.port, 443);
}

TEST(GatewayConfig, RejectsMalformedDocuments) {
    EXPECT_EQ(gw::parse_config("{", "/").error().problem, ConfigProblem::NotJson);
    EXPECT_EQ(gw::parse_config("[]", "/").error().problem, ConfigProblem::NotJson);
    const std::string twice = R"({"listen":{},"listen":{}})";
    EXPECT_EQ(gw::parse_config(twice, "/").error().problem, ConfigProblem::Duplicate);
    // 안쪽 객체의 중복 키도 막는다(마지막 값이 조용히 이기면 등급 정책이 바뀔 수 있다)
    std::string inner = valid().dump();
    inner.replace(inner.find("\"grade_policy\":\"o-only\""), 23, R"("grade_policy":"o-only","grade_policy":"declare")");
    EXPECT_EQ(gw::parse_config(inner, "/").error().problem, ConfigProblem::Duplicate);
}

TEST(GatewayConfig, RejectsUnknownAndMissingKeys) {
    json j = valid();
    j["debug"] = true;
    expect_error(j, ConfigProblem::UnknownKey, "debug");
    j = valid();
    j["provider"]["api_key"] = "x";
    expect_error(j, ConfigProblem::UnknownKey, "provider.api_key");
    j = valid();
    j.erase("origins");
    expect_error(j, ConfigProblem::Missing, "origins");
    j = valid();
    j["origins"] = json::array();
    expect_error(j, ConfigProblem::Missing, "origins");
    j = valid();
    j["listen"].erase("private_key");
    expect_error(j, ConfigProblem::Missing, "listen.private_key");
}

TEST(GatewayConfig, RejectsBadValues) {
    const auto with = [](const json::json_pointer& at, json value) {
        json j = valid();
        j[at] = std::move(value);
        return j;
    };
    expect_error(with("/listen/address"_json_pointer, "localhost"), ConfigProblem::InvalidValue, "listen.address");
    expect_error(with("/listen/port"_json_pointer, 0), ConfigProblem::InvalidValue, "listen.port");
    expect_error(with("/listen/port"_json_pointer, 70000), ConfigProblem::InvalidValue, "listen.port");
    expect_error(with("/listen/port"_json_pointer, "8443"), ConfigProblem::WrongType, "listen.port");
    expect_error(with("/listen/port"_json_pointer, 8443.5), ConfigProblem::WrongType, "listen.port");
    for (const char* url : {"http://127.0.0.1/v1", "https://user:pw@host/v1", "https://host", "https://host:0/v1",
                            "https://host:x/v1", "https://host/v1?key=1", "https:///v1", "https://[::1]/v1"}) {
        expect_error(with("/provider/url"_json_pointer, url), ConfigProblem::InvalidValue, "provider.url");
    }
    expect_error(with("/provider/model"_json_pointer, "two words"), ConfigProblem::InvalidValue, "provider.model");
    expect_error(with("/origins/0/name"_json_pointer, "Dept A"), ConfigProblem::InvalidValue, "origins[0].name");
    expect_error(with("/origins/0/token_sha256"_json_pointer, std::string(64, 'A')), ConfigProblem::InvalidValue,
                 "origins[0].token_sha256");
    expect_error(with("/origins/0/token_sha256"_json_pointer, std::string(63, 'a')), ConfigProblem::InvalidValue,
                 "origins[0].token_sha256");
    expect_error(with("/origins/0/grade_policy"_json_pointer, "O-ONLY"), ConfigProblem::InvalidValue,
                 "origins[0].grade_policy");
    expect_error(with("/origins/1/name"_json_pointer, "dept-a"), ConfigProblem::Duplicate, "origins[1].name");
    expect_error(with("/origins/1/token_sha256"_json_pointer, hash_a), ConfigProblem::Duplicate,
                 "origins[1].token_sha256");
    expect_error(with("/internal_terms/0"_json_pointer, ""), ConfigProblem::InvalidValue, "internal_terms[0]");
    expect_error(with("/internal_terms/0"_json_pointer, 3), ConfigProblem::WrongType, "internal_terms[0]");
    expect_error(with("/output_token_cap"_json_pointer, 0), ConfigProblem::InvalidValue, "output_token_cap");
    expect_error(with("/output_token_cap"_json_pointer, 65537), ConfigProblem::InvalidValue, "output_token_cap");
    expect_error(with("/output_token_cap"_json_pointer, -1), ConfigProblem::InvalidValue, "output_token_cap");
    expect_error(with("/history_retention_days"_json_pointer, 364), ConfigProblem::InvalidValue, "history_retention_days");
    EXPECT_EQ(parse(with("/history_retention_days"_json_pointer, 730))->history_retention_days, 730);
}

}  // namespace
