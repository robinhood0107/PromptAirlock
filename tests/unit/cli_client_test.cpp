#include "prompt_airlock/provider/cli_client.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <stdlib.h>
#endif

#include "prompt_airlock/extract/runner.hpp"

namespace {

namespace asio = boost::asio;
namespace ex = prompt_airlock::extract;
namespace gw = prompt_airlock::gateway;
namespace pv = prompt_airlock::provider;
using json = nlohmann::json;
using namespace std::chrono_literals;

void set_env(std::string_view name, const std::optional<std::string>& value) {
#ifdef _WIN32
    _putenv_s(std::string(name).c_str(), value ? value->c_str() : "");
#else
    if (value) setenv(std::string(name).c_str(), value->c_str(), 1);
    else unsetenv(std::string(name).c_str());
#endif
}

std::optional<std::string> get_env(const std::string& name) {
#ifdef _WIN32
    char* value = nullptr;
    std::size_t size = 0;
    if (_dupenv_s(&value, &size, name.c_str()) != 0 || value == nullptr) return std::nullopt;
    std::string result(value);
    std::free(value);
    return result;
#else
    const char* value = std::getenv(name.c_str());
    return value == nullptr ? std::nullopt : std::optional<std::string>(value);
#endif
}

class EnvironmentGuard {
public:
    EnvironmentGuard() {
        for (const auto& name : names_) {
            previous_.push_back(get_env(name));
        }
        profile_root_ = std::filesystem::temp_directory_path() /
                        ("pa-cli-profile-test-" +
                         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directory(profile_root_);
#ifdef _WIN32
        set_env("USERPROFILE", profile_root_.string());
#else
        set_env("HOME", profile_root_.string());
#endif
        set_env("OPENAI_API_KEY", "profile-a-secret");
        set_env("ANTHROPIC_API_KEY", "profile-b-secret");
        set_env("OPENAI_BASE_URL", "http://invalid.local");
        set_env("ANTHROPIC_BASE_URL", "http://invalid.local");
        set_env("WSLENV", "PROFILE_A/PROFILE_B");
        set_env("PA_CLI_TEST_UNEXPECTED", "profile-extra");
    }
    ~EnvironmentGuard() {
        for (std::size_t i = 0; i < names_.size(); ++i) set_env(names_[i], previous_[i]);
        std::filesystem::remove_all(profile_root_);
    }

    std::size_t call_count() const {
        std::ifstream input(profile_root_ / "cli-launch-count");
        std::size_t count = 0;
        for (std::string line; std::getline(input, line);) ++count;
        return count;
    }

private:
    const std::vector<std::string> names_ = {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_BASE_URL",
                                              "ANTHROPIC_BASE_URL", "WSLENV", "PA_CLI_TEST_UNEXPECTED",
                                              "HOME", "USERPROFILE"};
    std::vector<std::optional<std::string>> previous_;
    std::filesystem::path profile_root_;
};

std::expected<gw::ProviderReply, gw::ProviderError> send_cli(gw::CliOutputFormat format, std::string prompt,
                                                              std::uint32_t token_limit) {
    asio::thread_pool work(1);
    asio::io_context io;
    pv::CliClient client({PA_CLI_TEST_CHILD, format}, "test-model", work.get_executor());
    auto result = asio::co_spawn(io, client.send(std::move(prompt), token_limit), asio::use_future);
    io.run();
    work.join();
    return result.get();
}

std::string content(const gw::ProviderReply& reply) {
    const json body = json::parse(reply.body);
    return body["choices"][0]["message"]["content"].get<std::string>();
}

json expected_environment_report(const std::string& answer) {
    return json::parse(answer);
}

std::filesystem::path runner_directory() {
    auto path = std::filesystem::temp_directory_path() /
                ("pa-cli-runner-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directory(path);
    return path;
}

std::expected<std::string, ex::RunError> run_test_child(const std::filesystem::path& directory,
                                                        std::string mode, const ex::RunLimits& limits,
                                                        std::stop_token stop = {}) {
    const ex::ChildLaunchOptions launch{directory, {}, false};
    return ex::run_process(PA_CLI_TEST_CHILD, {"--runner-test", std::move(mode)}, {}, limits, stop, launch);
}

TEST(CliClient, JsonLinesUsesTheFixedToolFreeProfileAndSelectedEnvironment) {
    EnvironmentGuard guard;
    const auto result = send_cli(gw::CliOutputFormat::JsonLines, "SYNTHETIC_PROMPT", 8);
    ASSERT_TRUE(result);
    ASSERT_EQ(result->status, 200u);
    const json observed = expected_environment_report(content(*result));
    const json expected_argv = {"exec", "--skip-git-repo-check", "--ignore-user-config", "--ephemeral", "--json",
        "--disable", "shell_tool", "--disable", "unbounded_connection_retries", "--disable", "unified_exec",
        "--disable", "apps", "--disable", "hooks",
        "--disable", "multi_agent", "--disable", "browser_use", "--disable", "computer_use", "--disable",
        "image_generation", "--disable", "in_app_browser", "--disable", "in_app_local_automation", "--disable",
        "skill_search", "--disable", "goals", "-s", "read-only", "-c", "web_search=\"disabled\"",
        "--model", "test-model", "--color", "never", "-"};
    EXPECT_EQ(observed["argv"], expected_argv);
    EXPECT_TRUE(observed["cwd_empty"]);
    EXPECT_TRUE(observed["stdin_matches"]);
    EXPECT_TRUE(observed["selected_auth_matches"]);
    EXPECT_FALSE(observed["other_auth_present"]);
    EXPECT_FALSE(observed["base_override_present"]);
    EXPECT_FALSE(observed["wsl_env_present"]);
    EXPECT_FALSE(observed["unexpected_present"]);
    EXPECT_EQ(guard.call_count(), 1U);
    EXPECT_EQ(json::parse(result->body)["usage"]["completion_tokens"], 2);
    EXPECT_EQ(result->body.find("SYNTHETIC_REASONING_NOT_RETURNED"), std::string::npos);
    EXPECT_EQ(result->body.find("profile-a-secret"), std::string::npos);
}

TEST(CliClient, JsonFormatPreservesEmptyToolAndSettingSourceArguments) {
    EnvironmentGuard guard;
    const auto result = send_cli(gw::CliOutputFormat::Json, "SYNTHETIC_PROMPT", 8);
    ASSERT_TRUE(result);
    const json observed = expected_environment_report(content(*result));
    const json expected_argv = {"--bare", "--tools", "", "--strict-mcp-config", "--disable-slash-commands",
        "--no-session-persistence", "--print", "--output-format", "json", "--setting-sources", "",
        "--max-turns", "1", "--model", "test-model"};
    EXPECT_EQ(observed["argv"], expected_argv);
    EXPECT_TRUE(observed["cwd_empty"]);
    EXPECT_TRUE(observed["stdin_matches"]);
    EXPECT_TRUE(observed["selected_auth_matches"]);
    EXPECT_FALSE(observed["other_auth_present"]);
    EXPECT_FALSE(observed["base_override_present"]);
    EXPECT_FALSE(observed["wsl_env_present"]);
    EXPECT_FALSE(observed["unexpected_present"]);
    EXPECT_EQ(guard.call_count(), 1U);
}

TEST(CliClient, RejectsOutputThatExposesCredentialsOrExceedsTheRequestedTokenLimit) {
    EnvironmentGuard guard;
    const auto echoed_key = send_cli(gw::CliOutputFormat::JsonLines, "ECHO_KEY", 8);
    ASSERT_FALSE(echoed_key);
    EXPECT_EQ(echoed_key.error(), gw::ProviderError::BadResponse);
    const auto too_many = send_cli(gw::CliOutputFormat::JsonLines, "TOO_MANY_TOKENS", 8);
    ASSERT_FALSE(too_many);
    EXPECT_EQ(too_many.error(), gw::ProviderError::BadResponse);
}

TEST(CliClient, JsonLinesRejectsToolDuplicateAndTrailingEvents) {
    EnvironmentGuard guard;
    const std::vector<std::string> prompts = {"TOOL_ITEM", "DUPLICATE_ANSWER", "TRAILING_EVENT", "OUT_OF_ORDER"};
    for (const auto& prompt : prompts) {
        const auto result = send_cli(gw::CliOutputFormat::JsonLines, prompt, 8);
        ASSERT_FALSE(result) << prompt;
        EXPECT_EQ(result.error(), gw::ProviderError::BadResponse);
    }
    EXPECT_EQ(guard.call_count(), prompts.size());
}

TEST(CliClient, JsonLinesRequiresUsageRecognizedEventsAndExitZero) {
    EnvironmentGuard guard;
    const std::vector<std::string> prompts = {"MISSING_USAGE", "ERROR_EVENT", "NONZERO_EXIT"};
    for (const auto& prompt : prompts) {
        const auto result = send_cli(gw::CliOutputFormat::JsonLines, prompt, 8);
        ASSERT_FALSE(result) << prompt;
        EXPECT_EQ(result.error(), gw::ProviderError::BadResponse);
    }
    EXPECT_EQ(guard.call_count(), prompts.size());
}

TEST(CliClient, ProcessRunnerEnforcesExitTimeoutCancellationAndOutputLimit) {
    const auto directory = runner_directory();
    const ex::RunLimits quick{250ms, 128};
    const auto echo = run_test_child(directory, "echo", quick);
    ASSERT_TRUE(echo);
    EXPECT_TRUE(echo->empty());
    EXPECT_EQ(run_test_child(directory, "flood", quick).error(), ex::RunError::OutputTooLarge);
    EXPECT_EQ(run_test_child(directory, "sleep_close", quick).error(), ex::RunError::Timeout);

    std::stop_source source;
    std::promise<ex::RunError> cancelled;
    std::jthread worker([&] {
        cancelled.set_value(run_test_child(directory, "sleep_close", ex::RunLimits{5s, 128}, source.get_token()).error());
    });
    std::this_thread::sleep_for(100ms);
    source.request_stop();
    EXPECT_EQ(cancelled.get_future().get(), ex::RunError::Cancelled);
    worker.join();
    std::filesystem::remove_all(directory);
}

}  // namespace
