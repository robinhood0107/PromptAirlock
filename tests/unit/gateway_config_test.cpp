#include "prompt_airlock/gateway/config.hpp"
#include "prompt_airlock/core/sha256.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <barrier>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#endif

#if defined(__linux__)
#include <cerrno>
#include <csignal>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#endif

namespace {

namespace gw = prompt_airlock::gateway;
using gw::ConfigProblem;
using json = nlohmann::json;

const std::string hash_a(64, 'a');
const std::string hash_b(64, 'b');
const std::string hash_c(64, 'c');

json valid() {
    return {
        {"listen", {{"address", "127.0.0.1"}, {"port", 8443}, {"certificate_chain", "certs/server.pem"},
                    {"private_key", "certs/server.key"}}},
        {"provider", {{"url", "https://127.0.0.1:9443/v1/chat/completions"},
                      {"credential_file", "secrets/provider.key"},
                      {"trust_file", "certs/mock-ca.pem"},
                      {"model", "demo-model"}}},
        {"origins", json::array({{{"name", "dept-a"}, {"token_sha256", hash_a}, {"grade_policy", "o-only"}},
                                 {{"name", "dept-b"}, {"token_sha256", hash_b}, {"grade_policy", "declare"}},
                                 {{"name", "admin-console"}, {"token_sha256", hash_c}, {"grade_policy", "declare"}}})},
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

struct ConfigFileFixture {
    std::filesystem::path directory = std::filesystem::temp_directory_path() /
        ("pa-origin-file-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::path file = directory / "gateway.json";

    ConfigFileFixture() { std::filesystem::create_directories(directory); }
    ~ConfigFileFixture() { std::error_code ec; std::filesystem::remove_all(directory, ec); }

    void write(const json& value) const {
        std::ofstream output(file, std::ios::binary | std::ios::trunc);
        output << value.dump(2) << '\n';
    }

    std::string read() const {
        std::ifstream input(file, std::ios::binary);
        return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }
};

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
    EXPECT_TRUE(config->provider.credential_rotation_origin.empty());
    EXPECT_TRUE(config->admin_history_origin.empty());
    ASSERT_EQ(config->origins.size(), 3u);
    EXPECT_EQ(config->origins[0].grade_policy, prompt_airlock::core::GradePolicy::OOnly);
    EXPECT_EQ(config->origins[1].grade_policy, prompt_airlock::core::GradePolicy::Declare);
    EXPECT_EQ(config->origins[2].grade_policy, prompt_airlock::core::GradePolicy::Declare);
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
    EXPECT_FALSE(config->sentence_warn);
    j["sentence_warn"] = true;
    EXPECT_TRUE(parse(j)->sentence_warn);
    j["sentence_warn"] = "yes";
    EXPECT_FALSE(parse(j).has_value());
}

TEST(GatewayConfig, ProviderProtocolSettingsAreNarrowAndValidated) {
    auto j = valid();
    auto config = parse(j);
    ASSERT_TRUE(config);
    EXPECT_EQ(config->provider.protocol, gw::ProviderProtocol::ChatCompletions);
    EXPECT_EQ(config->provider.credential_mode, gw::ProviderCredentialMode::Bearer);

    j["provider"]["protocol"] = "generate_content";
    j["provider"]["credential_mode"] = "api_key_header";
    config = parse(j);
    ASSERT_TRUE(config);
    EXPECT_EQ(config->provider.protocol, gw::ProviderProtocol::GenerateContent);
    EXPECT_EQ(config->provider.credential_mode, gw::ProviderCredentialMode::ApiKeyHeader);

    j["provider"]["protocol"] = "messages";
    j["provider"].erase("credential_mode");
    j["provider"]["api_version_header_name"] = "x-test-version";
    j["provider"]["api_version_header_value"] = "2026-11-20";
    config = parse(j);
    ASSERT_TRUE(config);
    EXPECT_EQ(config->provider.protocol, gw::ProviderProtocol::Messages);
    EXPECT_EQ(config->provider.api_version_header_name, "x-test-version");

    j["provider"]["api_version_header_name"] = "x-invalid version";
    expect_error(j, ConfigProblem::InvalidValue, "provider.api_version_header_name");
    j["provider"]["api_version_header_name"] = "x-test";
    expect_error(j, ConfigProblem::InvalidValue, "provider.api_version_header_name");
    j["provider"]["api_version_header_name"] = "x-test-version";
    j["provider"]["api_version_header_value"] = "2026-13-20";
    expect_error(j, ConfigProblem::InvalidValue, "provider.api_version_header_value");
    j["provider"]["api_version_header_value"] = "2026-11-20\n";
    expect_error(j, ConfigProblem::InvalidValue, "provider.api_version_header_value");

    j["provider"]["credential_mode"] = "api_key_header";
    expect_error(j, ConfigProblem::InvalidValue, "provider.credential_mode");
    j = valid();
    j["provider"]["api_version_header_name"] = "x-test-version";
    expect_error(j, ConfigProblem::InvalidValue, "provider.api_version_header_name");
}

TEST(GatewayConfig, LocalCliUsesOnlyAConfiguredExecutableAndResultFormat) {
    auto j = valid();
    j["provider"] = {{"protocol", "local_cli"}, {"model", "demo-alias"},
                      {"cli", {{"executable", std::filesystem::temp_directory_path().string()},
                               {"result_format", "json_lines"}}}};
    auto config = parse(j);
    ASSERT_TRUE(config);
    EXPECT_EQ(config->provider.protocol, gw::ProviderProtocol::LocalCliText);
    EXPECT_EQ(config->provider.cli.output_format, gw::CliOutputFormat::JsonLines);
    EXPECT_TRUE(config->provider.cli.executable.is_absolute());

    j["provider"]["cli"]["arguments"] = json::array({"--unsafe"});
    expect_error(j, ConfigProblem::UnknownKey, "provider.cli.arguments");

#ifdef _WIN32
    j["provider"]["cli"].erase("arguments");
    j["provider"]["cli"]["executable"] = "C:\\Windows\\System32\\wsl.exe";
    expect_error(j, ConfigProblem::InvalidValue, "provider.cli.executable");
#endif
}

TEST(GatewayConfig, CredentialRotationRequiresOneRegisteredOrigin) {
    auto j = valid();
    j["provider"]["credential_rotation_origin"] = "dept-b";
    ASSERT_TRUE(parse(j));
    EXPECT_EQ(parse(j)->provider.credential_rotation_origin, "dept-b");
    j["provider"]["credential_rotation_origin"] = "missing-origin";
    expect_error(j, ConfigProblem::InvalidValue, "provider.credential_rotation_origin");
    j["provider"]["credential_rotation_origin"] = json::array({"dept-a", "dept-b"});
    expect_error(j, ConfigProblem::WrongType, "provider.credential_rotation_origin");
    j["provider"]["credential_rotation_origin"] = "";
    expect_error(j, ConfigProblem::InvalidValue, "provider.credential_rotation_origin");
}

TEST(GatewayConfig, AdminHistoryRequiresOneDedicatedRegisteredOrigin) {
    auto j = valid();
    j["admin_history_origin"] = "admin-console";
    ASSERT_TRUE(parse(j));
    EXPECT_EQ(parse(j)->admin_history_origin, "admin-console");
    j["admin_history_origin"] = "missing-origin";
    expect_error(j, ConfigProblem::InvalidValue, "admin_history_origin");
    j["admin_history_origin"] = json::array({"dept-a", "dept-b"});
    expect_error(j, ConfigProblem::WrongType, "admin_history_origin");
    j["admin_history_origin"] = "";
    expect_error(j, ConfigProblem::InvalidValue, "admin_history_origin");
    j["admin_history_origin"] = "admin-console";
    j["provider"]["credential_rotation_origin"] = "admin-console";
    expect_error(j, ConfigProblem::InvalidValue, "admin_history_origin");
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

TEST(GatewayConfig, ChatAppCompatibilityIsExplicitAndRejectsUnsafeOrUnknownOptions) {
    auto j = valid();
    EXPECT_FALSE(parse(j)->compat.chat_app);
    j["compat"] = {{"chat_app", true}};
    ASSERT_TRUE(parse(j));
    EXPECT_TRUE(parse(j)->compat.chat_app);
    j["listen"]["address"] = "192.0.2.10";
    expect_error(j, ConfigProblem::InvalidValue, "compat.chat_app");
    j = valid();
    j["compat"] = true;
    expect_error(j, ConfigProblem::WrongType, "compat");
    j["compat"] = {{"chat_app", "yes"}};
    expect_error(j, ConfigProblem::WrongType, "compat.chat_app");
    j["compat"] = {{"chat_app", true}, {"skip_checks", true}};
    expect_error(j, ConfigProblem::UnknownKey, "compat.skip_checks");
    j["compat"] = json::object();
    expect_error(j, ConfigProblem::Missing, "compat.chat_app");
    j["compat"] = {{"chat_app", true}};
    auto duplicate = j.dump();
    const auto offset = duplicate.find("\"chat_app\":true");
    ASSERT_NE(offset, std::string::npos);
    duplicate.replace(offset, 15, R"("chat_app":true,"chat_app":false)");
    const auto rejected = gw::parse_config(duplicate, "/etc/airlock");
    ASSERT_FALSE(rejected);
    EXPECT_EQ(rejected.error().problem, ConfigProblem::Duplicate);
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

TEST(GatewayConfig, ReadsInstitutionPolicy) {
    auto j = valid();
    j["policy"] = {{"industries", json::array({"hospital", "bank"})},
                   {"id_labels", json::array({"학번"})},
                   {"id_formats", json::array({"HR-####-###"})},
                   {"confidential_markers", json::array({"사내비"})},
                   {"confidential_subjects", json::array({"한빛 프로젝트"})}};
    const auto config = parse(j);
    ASSERT_TRUE(config.has_value());
    namespace pd = prompt_airlock::detect;
    EXPECT_EQ(config->policy.industries, (std::vector<pd::Industry>{pd::Industry::Hospital, pd::Industry::Bank}));
    EXPECT_EQ(config->policy.id_labels, std::vector<std::string>{"학번"});
    EXPECT_EQ(config->policy.id_formats.size(), 1U);
    EXPECT_EQ(config->policy.confidential_markers, std::vector<std::string>{"사내비"});
    EXPECT_EQ(config->policy.confidential_subjects, std::vector<std::string>{"한빛 프로젝트"});
    // 없으면 빈 정책이다(업종 표지어도 기관 번호 규칙도 없음).
    const auto plain = parse(valid());
    ASSERT_TRUE(plain.has_value());
    EXPECT_TRUE(plain->policy.industries.empty() && plain->policy.id_labels.empty() && plain->policy.id_formats.empty());
}

TEST(GatewayConfig, RejectsBadInstitutionPolicy) {
    const auto with = [](json policy) {
        auto j = valid();
        j["policy"] = std::move(policy);
        return j;
    };
    expect_error(with(json::array()), ConfigProblem::WrongType, "policy");
    expect_error(with({{"rules", json::array()}}), ConfigProblem::UnknownKey, "policy.rules");
    expect_error(with({{"industries", "bank"}}), ConfigProblem::WrongType, "policy.industries");
    expect_error(with({{"industries", json::array({"Bank"})}}), ConfigProblem::InvalidValue, "policy.industries[0]");
    expect_error(with({{"industries", json::array({"bank", "bank"})}}), ConfigProblem::Duplicate, "policy.industries[1]");
    expect_error(with({{"id_labels", json::array({""})}}), ConfigProblem::InvalidValue, "policy.id_labels[0]");
    expect_error(with({{"id_labels", json::array({1})}}), ConfigProblem::WrongType, "policy.id_labels[0]");
    expect_error(with({{"id_labels", json::array({std::string(33, 'a')})}}), ConfigProblem::InvalidValue,
                 "policy.id_labels[0]");
    expect_error(with({{"id_formats", json::array({"####"})}}), ConfigProblem::InvalidValue, "policy.id_formats[0]");
    expect_error(with({{"confidential_subjects", json::array({""})}}), ConfigProblem::InvalidValue,
                 "policy.confidential_subjects[0]");
    expect_error(with({{"confidential_markers", json::array({"a", "a"})}}), ConfigProblem::Duplicate,
                 "policy.confidential_markers[1]");
    json many = json::array();
    for (int i = 0; i < 17; ++i) {
        many.push_back("K" + std::to_string(i) + "-####");
    }
    expect_error(with({{"id_formats", many}}), ConfigProblem::InvalidValue, "policy.id_formats");
}

TEST(GatewayConfig, OriginFileUpdatesPreserveOtherSettingsAndReparse) {
    ConfigFileFixture fixture;
    auto initial = valid();
    initial["admin_history_origin"] = "admin-console";
    fixture.write(initial);
    const std::string token_hash(64, 'd');

    const auto added = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Add, "synthetic-app", token_hash,
                                               prompt_airlock::core::GradePolicy::OOnly);
    ASSERT_TRUE(added.has_value());
    ASSERT_EQ(added->size(), 4u);
    const auto listed = gw::manage_origin_file(fixture.file, gw::OriginFileAction::List);
    ASSERT_TRUE(listed.has_value());
    const auto found = std::ranges::find(*listed, "synthetic-app", &gw::Origin::name);
    ASSERT_NE(found, listed->end());
    EXPECT_EQ(found->token_sha256, token_hash);
    EXPECT_EQ(found->grade_policy, prompt_airlock::core::GradePolicy::OOnly);

    json before_other_fields = initial;
    before_other_fields.erase("origins");
    json after = json::parse(fixture.read());
    const auto stored = after["origins"].back();
    EXPECT_EQ(stored["name"], "synthetic-app");
    EXPECT_EQ(stored["token_sha256"], token_hash);
    EXPECT_EQ(stored["grade_policy"], "o-only");
    after.erase("origins");
    EXPECT_EQ(after, before_other_fields);

    const std::string current_text = fixture.read();
    const auto protected_origin = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Revoke, "admin-console");
    ASSERT_FALSE(protected_origin.has_value());
    EXPECT_EQ(protected_origin.error(), gw::OriginFileError::InUse);
    EXPECT_EQ(fixture.read(), current_text);

    const auto revoked = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Revoke, "dept-a");
    ASSERT_TRUE(revoked.has_value());
    EXPECT_EQ(revoked->size(), 3u);
    const auto after_revoke = gw::manage_origin_file(fixture.file, gw::OriginFileAction::List);
    ASSERT_TRUE(after_revoke.has_value());
    EXPECT_EQ(after_revoke->size(), 3u);
}

TEST(GatewayConfig, OriginFileValidationFailuresLeaveOriginalBytes) {
    ConfigFileFixture fixture;
    auto initial = valid();
    initial["provider"]["credential_rotation_origin"] = "dept-b";
    fixture.write(initial);
    const std::string original = fixture.read();

    const auto duplicate = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Add, "dept-a", std::string(64, 'e'));
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error(), gw::OriginFileError::Duplicate);
    EXPECT_EQ(fixture.read(), original);

    const auto referenced = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Revoke, "dept-b");
    ASSERT_FALSE(referenced.has_value());
    EXPECT_EQ(referenced.error(), gw::OriginFileError::InUse);
    EXPECT_EQ(fixture.read(), original);

    const auto missing = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Revoke, "missing-origin");
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error(), gw::OriginFileError::NotFound);
    EXPECT_EQ(fixture.read(), original);

    auto only_origin = valid();
    only_origin["origins"] = json::array({only_origin["origins"][0]});
    fixture.write(only_origin);
    const std::string one_origin = fixture.read();
    const auto last = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Revoke, "dept-a");
    ASSERT_FALSE(last.has_value());
    EXPECT_EQ(last.error(), gw::OriginFileError::LastOrigin);
    EXPECT_EQ(fixture.read(), one_origin);

    const std::string duplicate_json = R"({"duplicate":1,"duplicate":2})";
    {
        std::ofstream output(fixture.file, std::ios::binary | std::ios::trunc);
        output << duplicate_json;
    }
    const auto invalid = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Add, "new-origin", std::string(64, 'f'));
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error(), gw::OriginFileError::Duplicate);
    EXPECT_EQ(fixture.read(), duplicate_json);
}

TEST(GatewayConfig, ConcurrentOriginFileUpdatesDoNotLoseEntries) {
    ConfigFileFixture fixture;
    fixture.write(valid());
    constexpr std::size_t count = 8;
    std::barrier start(static_cast<std::ptrdiff_t>(count + 1));
    std::vector<int> succeeded(count, 0);
    std::vector<unsigned> failure_codes(count, 0);
    std::vector<std::thread> writers;
    writers.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        writers.emplace_back([&, i] {
            const std::string name = "concurrent-" + std::to_string(i);
            constexpr std::string_view hex = "0123456789abcdef";
            std::string hash(64, 'd');
            hash[62] = hex[i / 16];
            hash[63] = hex[i % 16];
            start.arrive_and_wait();
            const auto result = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Add, name, hash);
            succeeded[i] = result.has_value() ? 1 : 0;
            if (!result) failure_codes[i] = static_cast<unsigned>(result.error()) + 1;
        });
    }
    start.arrive_and_wait();
    for (auto& writer : writers) writer.join();
    for (const auto code : failure_codes) {
        if (code != 0) ADD_FAILURE() << "origin_file_error=" << code;
    }
    EXPECT_TRUE(std::ranges::all_of(succeeded, [](int value) { return value == 1; }));
    const auto listed = gw::manage_origin_file(fixture.file, gw::OriginFileAction::List);
    ASSERT_TRUE(listed.has_value());
    EXPECT_EQ(listed->size(), 3u + count);
}

#ifdef _WIN32
TEST(GatewayConfig, OriginFileReplacementFailureKeepsOriginalBytes) {
    ConfigFileFixture fixture;
    fixture.write(valid());
    const std::string original = fixture.read();
    HANDLE blocker = CreateFileW(fixture.file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(blocker, INVALID_HANDLE_VALUE);

    const auto result = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Add, "blocked-write",
                                               std::string(64, 'e'));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), gw::OriginFileError::WriteFailed);
    EXPECT_EQ(fixture.read(), original);
    EXPECT_EQ(CloseHandle(blocker), TRUE);
    for (const auto& entry : std::filesystem::directory_iterator(fixture.directory)) {
        EXPECT_EQ(entry.path().filename().string().find(".keys."), std::string::npos);
    }
}

TEST(GatewayConfig, OriginFileGlobalLockAccessFailureKeepsOriginalBytes) {
    ConfigFileFixture fixture;
    fixture.write(valid());
    const std::string original = fixture.read();
    const auto canonical = std::filesystem::canonical(fixture.file);
    const auto native = canonical.native();
    const int lower_size = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, native.c_str(), -1, nullptr, 0,
                                         nullptr, nullptr, 0);
    ASSERT_GT(lower_size, 0);
    std::wstring lower(static_cast<std::size_t>(lower_size), L'\0');
    ASSERT_NE(LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, native.c_str(), -1, lower.data(), lower_size,
                            nullptr, nullptr, 0), 0);
    lower.resize(static_cast<std::size_t>(lower_size - 1));
    const auto digest = prompt_airlock::core::sha256_hex(std::as_bytes(std::span(lower.data(), lower.size())));
    std::wstring mutex_name = L"Global\\PromptAirlock.Keys.";
    mutex_name.append(digest.begin(), digest.end());

    HANDLE process_token = nullptr;
    ASSERT_NE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &process_token), FALSE);
    DWORD token_size = 0;
    (void)GetTokenInformation(process_token, TokenUser, nullptr, 0, &token_size);
    ASSERT_GT(token_size, 0u);
    std::vector<std::byte> token_data(token_size);
    ASSERT_NE(GetTokenInformation(process_token, TokenUser, token_data.data(), token_size, &token_size), FALSE);
    ASSERT_NE(CloseHandle(process_token), FALSE);
    const auto* user = reinterpret_cast<const TOKEN_USER*>(token_data.data());

    std::vector<std::byte> acl_data(1024);
    PACL acl = reinterpret_cast<PACL>(acl_data.data());
    ASSERT_NE(InitializeAcl(acl, static_cast<DWORD>(acl_data.size()), ACL_REVISION), FALSE);
    ASSERT_NE(AddAccessDeniedAce(acl, ACL_REVISION, MUTEX_ALL_ACCESS, user->User.Sid), FALSE);
    SECURITY_DESCRIPTOR descriptor{};
    ASSERT_NE(InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION), FALSE);
    ASSERT_NE(SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE), FALSE);
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), &descriptor, FALSE};
    HANDLE inaccessible_mutex = CreateMutexW(&security, FALSE, mutex_name.c_str());
    ASSERT_NE(inaccessible_mutex, nullptr);

    const auto result = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Add, "lock-denied",
                                               std::string(64, 'e'));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), gw::OriginFileError::LockFailed);
    EXPECT_EQ(fixture.read(), original);
    EXPECT_EQ(CloseHandle(inaccessible_mutex), TRUE);
}
#endif

#if defined(__linux__)
TEST(GatewayConfig, OriginFileFailureKeepsOriginalWhenDirectoryIsReadOnly) {
    if (::geteuid() == 0) GTEST_SKIP() << "permission_denial_unavailable_as_root";
    ConfigFileFixture fixture;
    fixture.write(valid());
    const std::string original = fixture.read();
    std::error_code ec;
    const auto previous = std::filesystem::status(fixture.directory, ec).permissions();
    ASSERT_FALSE(ec);
    std::filesystem::permissions(fixture.directory, std::filesystem::perms::owner_read |
                                                       std::filesystem::perms::owner_exec,
                                 std::filesystem::perm_options::replace, ec);
    if (ec) GTEST_SKIP() << "temporary_directory_permission_change_unavailable";

    const auto result = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Add, "permission-denied",
                                               std::string(64, 'e'));
    std::filesystem::permissions(fixture.directory, previous, std::filesystem::perm_options::replace, ec);
    ASSERT_FALSE(ec);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), gw::OriginFileError::WriteFailed);
    EXPECT_EQ(fixture.read(), original);
    for (const auto& entry : std::filesystem::directory_iterator(fixture.directory)) {
        EXPECT_EQ(entry.path().filename().string().find(".keys."), std::string::npos);
    }
}

TEST(GatewayConfig, OriginFilePartialTempWriteKeepsOriginalBytes) {
    ConfigFileFixture fixture;
    fixture.write(valid());
    const std::string original = fixture.read();
    struct LimitRestore {
        struct rlimit limit {};
        using Handler = void (*)(int);
        Handler handler = SIG_DFL;
        bool saved_limit = false;
        bool saved_handler = false;
        void restore() {
            if (saved_limit) {
                (void)::setrlimit(RLIMIT_FSIZE, &limit);
                saved_limit = false;
            }
            if (saved_handler) {
                (void)std::signal(SIGXFSZ, handler);
                saved_handler = false;
            }
        }
        ~LimitRestore() { restore(); }
    } restore;
    if (::getrlimit(RLIMIT_FSIZE, &restore.limit) != 0) GTEST_SKIP() << "file_size_limit_unavailable";
    restore.saved_limit = true;
    restore.handler = std::signal(SIGXFSZ, SIG_IGN);
    if (restore.handler == SIG_ERR) GTEST_SKIP() << "file_size_signal_unavailable";
    restore.saved_handler = true;
    if (restore.limit.rlim_max < 1) GTEST_SKIP() << "file_size_limit_too_small";
    struct rlimit limited = restore.limit;
    limited.rlim_cur = 1;
    if (::setrlimit(RLIMIT_FSIZE, &limited) != 0) GTEST_SKIP() << "file_size_limit_change_unavailable";

    const auto result = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Add, "partial-write",
                                               std::string(64, 'f'));
    restore.restore();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), gw::OriginFileError::WriteFailed);
    EXPECT_EQ(fixture.read(), original);
    for (const auto& entry : std::filesystem::directory_iterator(fixture.directory)) {
        EXPECT_EQ(entry.path().filename().string().find(".keys."), std::string::npos);
    }
}

TEST(GatewayConfig, OriginFilePreservesPosixModeOwnerGroupAndXattrs) {
    ConfigFileFixture fixture;
    fixture.write(valid());
    constexpr char xattr_name[] = "user.promptairlock_test";
    constexpr char xattr_value[] = "synthetic-marker";
    if (::setxattr(fixture.file.c_str(), xattr_name, xattr_value, sizeof(xattr_value) - 1, 0) != 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == EPERM || errno == EACCES) {
            GTEST_SKIP() << "xattr_unavailable_on_test_filesystem";
        }
        FAIL() << "synthetic_xattr_setup_failed";
    }
    struct stat before {};
    ASSERT_EQ(::stat(fixture.file.c_str(), &before), 0);

    const auto result = gw::manage_origin_file(fixture.file, gw::OriginFileAction::Add, "xattr-test",
                                               std::string(64, 'e'));
    ASSERT_TRUE(result.has_value());
    struct stat after {};
    ASSERT_EQ(::stat(fixture.file.c_str(), &after), 0);
    EXPECT_EQ(after.st_mode & 07777, before.st_mode & 07777);
    EXPECT_EQ(after.st_uid, before.st_uid);
    EXPECT_EQ(after.st_gid, before.st_gid);
    char actual[sizeof(xattr_value)]{};
    const auto size = ::getxattr(fixture.file.c_str(), xattr_name, actual, sizeof(actual));
    ASSERT_EQ(size, static_cast<ssize_t>(sizeof(xattr_value) - 1));
    EXPECT_EQ(std::string_view(actual, static_cast<std::size_t>(size)), xattr_value);
}
#endif
