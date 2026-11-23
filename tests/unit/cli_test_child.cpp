#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <string_view>

#ifdef _WIN32
#include <io.h>
#include <stdlib.h>
#else
#include <unistd.h>
#endif

#include "test_cert.hpp"

namespace {

using json = nlohmann::json;

std::optional<std::string> environment_value(const char* name) {
#ifdef _WIN32
    char* value = nullptr;
    std::size_t size = 0;
    if (_dupenv_s(&value, &size, name) != 0 || value == nullptr) return std::nullopt;
    std::string result(value);
    std::free(value);
    return result;
#else
    const char* value = std::getenv(name);
    return value == nullptr ? std::nullopt : std::optional<std::string>(value);
#endif
}

bool present(const char* name) { return environment_value(name).has_value(); }

std::string env_or_empty(const char* name) {
    return environment_value(name).value_or(std::string());
}

int runner_child(int argc, char** argv) {
    std::string input(std::istreambuf_iterator<char>(std::cin), {});
    const std::string mode = argc > 2 ? argv[2] : "";
    if (mode == "echo") {
        std::cout << input;
        return 0;
    }
    if (mode == "flood") {
        std::cout << std::string(4096, 'x');
        return 0;
    }
    if (mode == "sleep_close") {
        std::cout.flush();
#ifdef _WIN32
        _close(1);
#else
        ::close(STDOUT_FILENO);
#endif
        std::this_thread::sleep_for(std::chrono::seconds(10));
        return 0;
    }
    return 9;
}

int main_cli(int argc, char** argv) {
    const bool profile_a = argc > 1 && std::string_view(argv[1]) == "--bare";
    const auto selected_value = env_or_empty(profile_a ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY");
    json report = {
        {"argv", json::array()},
        {"cwd_empty", std::filesystem::directory_iterator(std::filesystem::current_path()) ==
                           std::filesystem::directory_iterator()},
        {"stdin_matches", false},
        {"selected_auth_matches", selected_value == (profile_a ? "profile-b-secret" : "profile-a-secret")},
        {"other_auth_present", present(profile_a ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY")},
        {"base_override_present", present("OPENAI_BASE_URL") || present("ANTHROPIC_BASE_URL")},
        {"wsl_env_present", present("WSLENV")},
        {"unexpected_present", present("PA_CLI_TEST_UNEXPECTED")},
    };
    for (int i = 1; i < argc; ++i) report["argv"].push_back(argv[i]);

    std::string input(std::istreambuf_iterator<char>(std::cin), {});
#ifdef _WIN32
    const auto root = environment_value("USERPROFILE");
#else
    const auto root = environment_value("HOME");
#endif
    if (root) {
        std::ofstream(std::filesystem::path(*root) / "cli-launch-count", std::ios::app) << "x\n";
    }
    report["stdin_matches"] = input == "SYNTHETIC_PROMPT";
    std::string answer = report.dump();
    std::int64_t output_tokens = 2;
    if (input == "GATEWAY_LAUNCH") answer = "MOCK_TEXT_ONLY";
    if (input == "ECHO_KEY") answer = selected_value;
    if (input == "TOO_MANY_TOKENS") output_tokens = 100;

    if (profile_a) {
        std::cout << json{{"result", answer}, {"num_turns", 1},
                          {"usage", {{"input_tokens", 3}, {"output_tokens", output_tokens}}}}.dump();
        return 0;
    }
    std::cout << json{{"type", "thread.started"}}.dump() << '\n';
    std::cout << json{{"type", "turn.started"}}.dump() << '\n';
    std::cout << json{{"type", "item.completed"},
                      {"item", {{"type", "agent_message"}, {"text", answer}}}}.dump()
              << '\n';
    std::cout << json{{"type", "turn.completed"}, {"status", "completed"},
                      {"usage", {{"input_tokens", 3}, {"output_tokens", output_tokens}}}}.dump()
              << '\n';
    std::cout << json{{"type", "result"}, {"subtype", "success"}, {"is_error", false}, {"num_turns", 1},
                      {"stop_reason", "end_turn"}, {"result", answer},
                      {"usage", {{"input_tokens", 3}, {"output_tokens", output_tokens}}}}.dump()
              << '\n';
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 4 && std::string_view(argv[1]) == "--write-cert") {
        const auto certificate = pa_test::make_test_certificate();
        std::ofstream(argv[2], std::ios::binary) << certificate.certificate_pem;
        std::ofstream(argv[3], std::ios::binary) << certificate.private_key_pem;
        return 0;
    }
    if (argc > 1 && std::string_view(argv[1]) == "--runner-test") return runner_child(argc, argv);
    return main_cli(argc, argv);
}
