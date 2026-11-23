#include "prompt_airlock/provider/cli_client.hpp"

#include <boost/asio/associated_cancellation_slot.hpp>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <expected>
#include <filesystem>
#include <limits>
#include <set>
#include <span>
#include <stop_token>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <atomic>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "prompt_airlock/core/sensitive.hpp"
#include "prompt_airlock/extract/runner.hpp"
#include "prompt_airlock/gateway/request_json.hpp"
#include "prompt_airlock/gateway/response_json.hpp"

namespace prompt_airlock::provider {
namespace {

namespace asio = boost::asio;
namespace json = nlohmann;
using Result = std::expected<gateway::ProviderReply, gateway::ProviderError>;
using namespace std::chrono_literals;

constexpr extract::RunLimits cli_limits{110s, 1U << 20};
#ifdef _WIN32
std::atomic<std::uint64_t> work_directory_counter{0};
#endif

struct SensitiveString {
    std::string value;
    ~SensitiveString() { core::secure_wipe(std::span<char>{value.data(), value.size()}); }
};

struct SensitiveEnvironment {
    std::vector<std::string> values;
    ~SensitiveEnvironment() {
        for (auto& value : values) core::secure_wipe(std::span<char>{value.data(), value.size()});
    }
};

struct SensitiveLaunch {
    extract::ChildLaunchOptions options;
    ~SensitiveLaunch() {
        for (auto& value : options.environment) core::secure_wipe(std::span<char>{value.data(), value.size()});
    }
};

struct WorkDirectory {
    std::filesystem::path path;

    WorkDirectory() = default;
    explicit WorkDirectory(std::filesystem::path value) : path(std::move(value)) {}
    WorkDirectory(WorkDirectory&& other) noexcept : path(std::move(other.path)) { other.path.clear(); }
    WorkDirectory& operator=(WorkDirectory&& other) noexcept {
        if (this != &other) {
            cleanup();
            path = std::move(other.path);
            other.path.clear();
        }
        return *this;
    }
    WorkDirectory(const WorkDirectory&) = delete;
    WorkDirectory& operator=(const WorkDirectory&) = delete;
    ~WorkDirectory() { cleanup(); }

    bool cleanup() noexcept {
        if (path.empty()) return true;
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
        if (ec) return false;
        path.clear();
        return true;
    }
};

std::expected<WorkDirectory, gateway::ProviderError> make_work_directory() {
    std::error_code ec;
    const auto base = std::filesystem::temp_directory_path(ec);
    if (ec) return std::unexpected(gateway::ProviderError::Unavailable);
#ifndef _WIN32
    std::string pattern = (base / "pa-cli-relay-XXXXXX").string();
    char* created = ::mkdtemp(pattern.data());
    if (created == nullptr) return std::unexpected(gateway::ProviderError::Unavailable);
    const int fd = ::open(created, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat info{};
    const bool private_directory = fd >= 0 && ::fstat(fd, &info) == 0 && info.st_uid == ::geteuid() &&
                                   (info.st_mode & 0777) == 0700;
    if (fd >= 0) ::close(fd);
    if (!private_directory) {
        std::filesystem::remove(created, ec);
        return std::unexpected(gateway::ProviderError::Unavailable);
    }
    return WorkDirectory(std::filesystem::path(created));
#else
    const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        const auto sequence = work_directory_counter.fetch_add(1, std::memory_order_relaxed);
        const auto path = base / ("pa-cli-relay-" + std::to_string(tick) + "-" + std::to_string(sequence));
        if (!std::filesystem::create_directory(path, ec)) {
            if (ec) return std::unexpected(gateway::ProviderError::Unavailable);
            continue;
        }
        return WorkDirectory(path);
    }
    return std::unexpected(gateway::ProviderError::Unavailable);
#endif
}

#ifdef _WIN32
std::string get_environment_value(std::string_view name) {
    std::wstring wide_name(name.begin(), name.end());
    const DWORD required = GetEnvironmentVariableW(wide_name.c_str(), nullptr, 0);
    if (required == 0) return {};
    std::wstring value(required, L'\0');
    const DWORD length = GetEnvironmentVariableW(wide_name.c_str(), value.data(), required);
    if (length == 0 || length >= required) return {};
    value.resize(length);
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return {};
    std::string result(static_cast<std::size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                            result.data(), bytes, nullptr, nullptr) != bytes) {
        return {};
    }
    return result;
}
#else
std::string get_environment_value(std::string_view name) {
    const std::string owned(name);
    const char* value = std::getenv(owned.c_str());
    return value != nullptr ? value : std::string();
}
#endif

SensitiveEnvironment limited_environment(gateway::CliOutputFormat format) {
    SensitiveEnvironment environment;
    std::set<std::string, std::less<>> names;
    const auto append = [&](std::string_view name, std::string value) {
        if (!value.empty() && names.insert(std::string(name)).second) {
            environment.values.emplace_back(std::string(name) + "=" + value);
        }
        core::secure_wipe(std::span<char>{value.data(), value.size()});
    };
#ifdef _WIN32
    constexpr std::array<std::string_view, 8> common = {
        "SystemRoot", "WINDIR", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "PATH"};
#else
    constexpr std::array<std::string_view, 5> common = {"HOME", "PATH", "LANG", "LC_ALL", "TERM"};
#endif
    for (const auto name : common) append(name, get_environment_value(name));
    append(format == gateway::CliOutputFormat::Json ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY",
           get_environment_value(format == gateway::CliOutputFormat::Json ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY"));
    environment.values.emplace_back("NO_COLOR=1");
    environment.values.emplace_back("DISABLE_AUTOUPDATER=1");
    return environment;
}

class DuplicateKeyGuard {
public:
    bool operator()(int depth, json::json::parse_event_t event, json::json& value) {
        if (depth < 0 || depth > static_cast<int>(gateway::max_json_depth)) {
            invalid = true;
            return true;
        }
        const auto level = static_cast<std::size_t>(depth);
        if (event == json::json::parse_event_t::object_start) {
            if (keys.size() <= level) keys.resize(level + 1);
            keys[level].clear();
        } else if (event == json::json::parse_event_t::key && level > 0) {
            if (keys.size() < level || !keys[level - 1].insert(value.get<std::string>()).second) invalid = true;
        }
        return true;
    }

    bool invalid = false;

private:
    std::vector<std::set<std::string>> keys;
};

std::optional<std::int64_t> nonnegative_integer(const json::json& object, std::string_view key) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_number_integer()) return std::nullopt;
    const std::int64_t value = it->get<std::int64_t>();
    return value >= 0 ? std::optional(value) : std::nullopt;
}

struct ParsedCliAnswer {
    std::string text;
    gateway::Usage usage;
};

bool contains_secret(std::string_view text, const SensitiveEnvironment& environment) {
    for (const auto& entry : environment.values) {
        const auto equals = entry.find('=');
        if (equals == std::string::npos) continue;
        const auto name = std::string_view(entry).substr(0, equals);
        if (name.ends_with("_API_KEY")) {
            const auto value = std::string_view(entry).substr(equals + 1);
            if (!value.empty() && text.find(value) != std::string_view::npos) return true;
        }
    }
    return false;
}

std::expected<ParsedCliAnswer, gateway::ProviderError> parse_json_answer(
    std::string_view output, std::uint32_t output_token_limit, const SensitiveEnvironment& environment) {
    DuplicateKeyGuard guard;
    const json::json root = json::json::parse(output, std::ref(guard), false, true);
    if (root.is_discarded() || guard.invalid || !root.is_object() || !root.contains("result") ||
        !root["result"].is_string() || (root.contains("is_error") && root["is_error"] != false) ||
        !root.contains("num_turns") || !root["num_turns"].is_number_integer() || root["num_turns"] != 1 ||
        !root.contains("usage") || !root["usage"].is_object()) {
        return std::unexpected(gateway::ProviderError::BadResponse);
    }
    const auto input = nonnegative_integer(root["usage"], "input_tokens");
    const auto completion = nonnegative_integer(root["usage"], "output_tokens");
    if (!input || !completion || *completion > output_token_limit ||
        *input > std::numeric_limits<std::int64_t>::max() - *completion) {
        return std::unexpected(gateway::ProviderError::BadResponse);
    }
    std::string text = root["result"].get<std::string>();
    if (text.empty() || contains_secret(text, environment)) {
        core::secure_wipe(std::span<char>{text.data(), text.size()});
        return std::unexpected(gateway::ProviderError::BadResponse);
    }
    return ParsedCliAnswer{std::move(text), {*input, *completion, *input + *completion}};
}

std::expected<ParsedCliAnswer, gateway::ProviderError> parse_json_lines_answer(
    std::string_view output, std::uint32_t output_token_limit, const SensitiveEnvironment& environment) {
    SensitiveString text;
    std::optional<gateway::Usage> usage;
    bool thread_started = false;
    bool turn_started = false;
    bool answer_seen = false;
    bool turn_completed = false;
    std::size_t start = 0;
    while (start < output.size()) {
        const auto end = output.find('\n', start);
        std::string_view line = output.substr(start, end == std::string_view::npos ? output.size() - start : end - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        start = end == std::string_view::npos ? output.size() : end + 1;
        if (line.empty()) continue;
        DuplicateKeyGuard guard;
        const json::json event = json::json::parse(line, std::ref(guard), false, true);
        if (event.is_discarded() || guard.invalid || !event.is_object() || !event.contains("type") ||
            !event["type"].is_string()) {
            return std::unexpected(gateway::ProviderError::BadResponse);
        }
        if (turn_completed) return std::unexpected(gateway::ProviderError::BadResponse);
        const std::string type = event["type"].get<std::string>();
        if (type == "thread.started") {
            if (thread_started || turn_started) return std::unexpected(gateway::ProviderError::BadResponse);
            thread_started = true;
            continue;
        }
        if (type == "turn.started") {
            if (!thread_started || turn_started) return std::unexpected(gateway::ProviderError::BadResponse);
            turn_started = true;
            continue;
        }
        if (type == "item.completed") {
            if (!turn_started || !event.contains("item") || !event["item"].is_object() ||
                !event["item"].contains("type") || !event["item"]["type"].is_string()) {
                return std::unexpected(gateway::ProviderError::BadResponse);
            }
            const auto& item = event["item"];
            const std::string item_type = item["type"].get<std::string>();
            if (item_type == "reasoning") {
                if (answer_seen) return std::unexpected(gateway::ProviderError::BadResponse);
                continue;
            }
            if (item_type != "agent_message" || answer_seen || !item.contains("text") || !item["text"].is_string()) {
                return std::unexpected(gateway::ProviderError::BadResponse);
            }
            text.value = item["text"].get<std::string>();
            answer_seen = true;
            continue;
        }
        if (type == "turn.completed") {
            if (!turn_started || turn_completed || !answer_seen || !event.contains("usage") ||
                !event["usage"].is_object()) {
                return std::unexpected(gateway::ProviderError::BadResponse);
            }
            const auto input = nonnegative_integer(event["usage"], "input_tokens");
            const auto completion = nonnegative_integer(event["usage"], "output_tokens");
            if (!input || !completion || *completion > output_token_limit ||
                *input > std::numeric_limits<std::int64_t>::max() - *completion) {
                return std::unexpected(gateway::ProviderError::BadResponse);
            }
            if (event.contains("status") && event["status"] != "completed") {
                return std::unexpected(gateway::ProviderError::BadResponse);
            }
            usage = gateway::Usage{*input, *completion, *input + *completion};
            turn_completed = true;
            continue;
        }
        return std::unexpected(gateway::ProviderError::BadResponse);
    }
    if (!turn_completed || !usage || text.value.empty() || contains_secret(text.value, environment)) {
        return std::unexpected(gateway::ProviderError::BadResponse);
    }
    return ParsedCliAnswer{std::move(text.value), *usage};
}

std::vector<std::string> cli_arguments(gateway::CliOutputFormat format, std::string_view model) {
    if (format == gateway::CliOutputFormat::Json) {
        return {"--bare", "--tools", "", "--strict-mcp-config", "--disable-slash-commands",
                "--no-session-persistence", "--print", "--output-format", "json", "--setting-sources", "",
                "--max-turns", "1", "--model", std::string(model)};
    }
    return {"exec", "--skip-git-repo-check", "--ignore-user-config", "--ephemeral", "--json",
            "--disable", "shell_tool", "--disable", "unbounded_connection_retries", "--disable", "unified_exec",
            "--disable", "apps", "--disable", "hooks",
            "--disable", "multi_agent", "--disable", "browser_use", "--disable", "computer_use", "--disable",
            "image_generation", "--disable", "in_app_browser", "--disable", "in_app_local_automation", "--disable",
            "skill_search", "--disable", "goals", "-s", "read-only", "-c", "web_search=\"disabled\"",
            "--model", std::string(model), "--color", "never", "-"};
}

void wipe(std::string& value) noexcept { core::secure_wipe(std::span<char>{value.data(), value.size()}); }

Result run_cli(const gateway::CliConfig& config, std::string model, std::string prompt,
               std::uint32_t output_token_limit, std::stop_token stop) {
    SensitiveString prompt_buffer{std::move(prompt)};
    auto directory = make_work_directory();
    if (!directory) return std::unexpected(directory.error());
    SensitiveEnvironment environment = limited_environment(config.output_format);
    SensitiveLaunch launch;
    launch.options.working_directory = directory->path;
    launch.options.environment = environment.values;
    launch.options.inherit_environment = false;
    const auto args = cli_arguments(config.output_format, model);
    extract::RunLimits limits = cli_limits;
    const auto input = std::as_bytes(std::span(prompt_buffer.value.data(), prompt_buffer.value.size()));
    auto output = extract::run_process(config.executable, args, input, limits, stop, launch.options);
    if (!directory->cleanup()) {
        if (output) wipe(*output);
        return std::unexpected(gateway::ProviderError::Unavailable);
    }
    if (!output) {
        if (output.error() == extract::RunError::Timeout) return std::unexpected(gateway::ProviderError::Timeout);
        if (output.error() == extract::RunError::Cancelled) return std::unexpected(gateway::ProviderError::Unavailable);
        if (output.error() == extract::RunError::StartFailed) return std::unexpected(gateway::ProviderError::Unavailable);
        return std::unexpected(gateway::ProviderError::BadResponse);
    }
    SensitiveString raw{std::move(*output)};
    auto parsed = config.output_format == gateway::CliOutputFormat::Json
        ? parse_json_answer(raw.value, output_token_limit, environment)
        : parse_json_lines_answer(raw.value, output_token_limit, environment);
    if (!parsed) return std::unexpected(parsed.error());
    SensitiveString text{std::move(parsed->text)};
    return gateway::ProviderReply{200, gateway::client_response_body("cli", 0, model, text.value, "stop",
                                                                      std::optional{parsed->usage})};
}

}  // namespace

CliClient::CliClient(gateway::CliConfig config, std::string model_alias, asio::any_io_executor work)
    : config_(std::move(config)), model_alias_(std::move(model_alias)), work_(std::move(work)) {}

asio::awaitable<Result> CliClient::send(std::string prompt, std::uint32_t output_token_limit) const {
    auto state = std::make_shared<std::stop_source>();
    auto prompt_buffer = std::make_shared<SensitiveString>(std::move(prompt));
    co_return co_await asio::async_initiate<const asio::use_awaitable_t<>, void(std::exception_ptr, Result)>(
        [this, state, prompt_buffer = std::move(prompt_buffer), output_token_limit](auto handler) mutable {
            if (auto slot = asio::get_associated_cancellation_slot(handler); slot.is_connected()) {
                slot.assign([state](asio::cancellation_type) { state->request_stop(); });
            }
            asio::post(work_, [this, state, prompt_buffer = std::move(prompt_buffer), output_token_limit,
                               handler = std::move(handler)]() mutable {
                Result result;
                try {
                    result = run_cli(config_, model_alias_, std::move(prompt_buffer->value), output_token_limit,
                                     state->get_token());
                } catch (...) {
                    result = std::unexpected(gateway::ProviderError::BadResponse);
                }
                const auto home = asio::get_associated_executor(handler);
                asio::post(home, [handler = std::move(handler), result = std::move(result)]() mutable {
                    asio::get_associated_cancellation_slot(handler).clear();
                    std::move(handler)(std::exception_ptr{}, std::move(result));
                });
            });
        },
        asio::use_awaitable);
}

}  // namespace prompt_airlock::provider
