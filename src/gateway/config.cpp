#include "prompt_airlock/gateway/config.hpp"

#include <boost/asio/ip/address.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cctype>
#include <chrono>
#include <cstring>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <optional>
#include <set>
#include <span>
#include <utility>

#include "prompt_airlock/core/sha256.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#endif

namespace prompt_airlock::gateway {
namespace {

using json = nlohmann::json;
using Result = std::expected<void, ConfigError>;

std::unexpected<ConfigError> fail(ConfigProblem problem, std::string field) {
    return std::unexpected(ConfigError{problem, std::move(field)});
}

// 객체에 허용된 키만 있는지 본다.
Result only_keys(const json& object, std::initializer_list<std::string_view> allowed, const std::string& at) {
    for (const auto& [key, value] : object.items()) {
        if (std::ranges::find(allowed, key) == allowed.end()) {
            return fail(ConfigProblem::UnknownKey, at.empty() ? key : at + "." + key);
        }
    }
    return {};
}

std::expected<const json*, ConfigError> member(const json& object, std::string_view key, const std::string& at,
                                               json::value_t type) {
    const std::string field = at.empty() ? std::string(key) : at + "." + std::string(key);
    const auto it = object.find(key);
    if (it == object.end()) {
        return fail(ConfigProblem::Missing, field);
    }
    const bool number_ok = type == json::value_t::number_unsigned && it->is_number_integer();
    if (it->type() != type && !number_ok) {
        return fail(ConfigProblem::WrongType, field);
    }
    return &*it;
}

std::expected<std::string, ConfigError> text(const json& object, std::string_view key, const std::string& at) {
    auto value = member(object, key, at, json::value_t::string);
    if (!value) {
        return std::unexpected(value.error());
    }
    auto s = (*value)->get<std::string>();
    if (s.empty()) {
        return fail(ConfigProblem::InvalidValue, at + "." + std::string(key));
    }
    return s;
}

std::expected<std::uint16_t, ConfigError> port_number(const json& object, std::string_view key, const std::string& at) {
    auto value = member(object, key, at, json::value_t::number_unsigned);
    if (!value) {
        return std::unexpected(value.error());
    }
    const auto n = (*value)->get<std::int64_t>();
    if (n < 1 || n > 65535) {
        return fail(ConfigProblem::InvalidValue, at + "." + std::string(key));
    }
    return static_cast<std::uint16_t>(n);
}

std::filesystem::path resolve(const std::filesystem::path& base, const std::string& value) {
    std::filesystem::path p(std::u8string(value.begin(), value.end()));
    return p.is_absolute() ? p : base / p;
}

bool printable_ascii(std::string_view s) {
    return std::ranges::all_of(s, [](char c) { return c > 0x20 && c < 0x7f; });
}

// 출처 이름: 소문자·숫자·'-', 1~64자. 감사 기록과 응답에 그대로 쓰이므로 좁게 둔다.
bool valid_origin_name(std::string_view s) {
    return !s.empty() && s.size() <= 64 &&
           std::ranges::all_of(s, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
}

bool lowercase_sha256_hex(std::string_view s) {
    return s.size() == 64 && std::ranges::all_of(s, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

bool valid_header_token(std::string_view name) {
    constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
    return !name.empty() && std::ranges::all_of(name, [&](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               punctuation.find(static_cast<char>(c)) != std::string_view::npos;
    });
}

bool valid_api_version_date(std::string_view value) {
    if (value.size() != 10 || value[4] != '-' || value[7] != '-') return false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i != 4 && i != 7 && (value[i] < '0' || value[i] > '9')) return false;
    }
    const auto number = [&](std::size_t first, std::size_t count) {
        unsigned result = 0;
        for (std::size_t i = first; i < first + count; ++i) result = result * 10 + static_cast<unsigned>(value[i] - '0');
        return result;
    };
    const std::chrono::year_month_day date{std::chrono::year{static_cast<int>(number(0, 4))},
                                           std::chrono::month{number(5, 2)}, std::chrono::day{number(8, 2)}};
    return date.ok();
}

Result parse_cli_config(const json& provider, const std::string& at, CliConfig& out) {
    auto node = member(provider, "cli", at, json::value_t::object);
    if (!node) return std::unexpected(node.error());
    const json& cli = **node;
    const std::string field = at + ".cli";
    if (auto r = only_keys(cli, {"executable", "result_format"}, field); !r) return r;
    auto executable = text(cli, "executable", field);
    auto format = text(cli, "result_format", field);
    if (!executable) return std::unexpected(executable.error());
    if (!format) return std::unexpected(format.error());
    if (executable->size() > 4096) return fail(ConfigProblem::InvalidValue, field + ".executable");
    out.executable = std::filesystem::path(std::u8string(executable->begin(), executable->end()));
    if (!out.executable.is_absolute()) return fail(ConfigProblem::InvalidValue, field + ".executable");
#ifdef _WIN32
    std::string executable_name = out.executable.filename().string();
    std::ranges::transform(executable_name, executable_name.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (executable_name == "wsl.exe") return fail(ConfigProblem::InvalidValue, field + ".executable");
#endif
    if (*format == "json") out.output_format = CliOutputFormat::Json;
    else if (*format == "json_lines") out.output_format = CliOutputFormat::JsonLines;
    else return fail(ConfigProblem::InvalidValue, field + ".result_format");
    return {};
}

// https://host[:port]/path 만 받는다. 사용자 정보·질의·조각은 거절한다(자격 증명은 별도 파일).
Result parse_provider_url(std::string_view url, ProviderConfig& out) {
    constexpr std::string_view scheme = "https://";
    const std::string field = "provider.url";
    if (!url.starts_with(scheme) || !printable_ascii(url) || url.find_first_of("@?#\\") != std::string_view::npos) {
        return fail(ConfigProblem::InvalidValue, field);
    }
    url.remove_prefix(scheme.size());
    const auto slash = url.find('/');
    if (slash == std::string_view::npos) {
        return fail(ConfigProblem::InvalidValue, field);
    }
    std::string_view authority = url.substr(0, slash);
    out.target = std::string(url.substr(slash));
    if (const auto colon = authority.rfind(':'); colon != std::string_view::npos && authority.find(']') == std::string_view::npos) {
        const std::string_view digits = authority.substr(colon + 1);
        unsigned value = 0;
        const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
        if (digits.empty() || ec != std::errc{} || end != digits.data() + digits.size() || value < 1 || value > 65535) {
            return fail(ConfigProblem::InvalidValue, field);
        }
        out.port = static_cast<std::uint16_t>(value);
        authority = authority.substr(0, colon);
    }
    if (authority.empty() || authority.find('[') != std::string_view::npos) {  // IPv6 문자 주소는 아직 받지 않는다
        return fail(ConfigProblem::InvalidValue, field);
    }
    out.host = std::string(authority);
    return {};
}

Result parse_listen(const json& root, const std::filesystem::path& base, ListenConfig& out) {
    const std::string at = "listen";
    auto node = member(root, at, "", json::value_t::object);
    if (!node) {
        return std::unexpected(node.error());
    }
    const json& o = **node;
    if (auto r = only_keys(o, {"address", "port", "certificate_chain", "private_key"}, at); !r) {
        return r;
    }
    auto address = text(o, "address", at);
    auto port = port_number(o, "port", at);
    auto cert = text(o, "certificate_chain", at);
    auto key = text(o, "private_key", at);
    if (!address) return std::unexpected(address.error());
    if (!port) return std::unexpected(port.error());
    if (!cert) return std::unexpected(cert.error());
    if (!key) return std::unexpected(key.error());
    boost::system::error_code ec;
    (void)boost::asio::ip::make_address(*address, ec);
    if (ec) {
        return fail(ConfigProblem::InvalidValue, "listen.address");
    }
    out = {std::move(*address), *port, resolve(base, *cert), resolve(base, *key)};
    return {};
}

Result parse_provider(const json& root, const std::filesystem::path& base, ProviderConfig& out) {
    const std::string at = "provider";
    auto node = member(root, at, "", json::value_t::object);
    if (!node) {
        return std::unexpected(node.error());
    }
    const json& o = **node;
    if (auto r = only_keys(o, {"url", "credential_file", "trust_file", "model", "credential_rotation_origin", "protocol",
                               "credential_mode", "api_version_header_name", "api_version_header_value", "cli"}, at);
        !r) {
        return r;
    }
    auto model = text(o, "model", at);
    if (!model) return std::unexpected(model.error());
    if (model->size() > 128 || !printable_ascii(*model)) {
        return fail(ConfigProblem::InvalidValue, "provider.model");
    }
    out.model = std::move(*model);
    if (o.contains("protocol")) {
        auto protocol = text(o, "protocol", at);
        if (!protocol) return std::unexpected(protocol.error());
        if (*protocol == "chat_completions") {
            out.protocol = ProviderProtocol::ChatCompletions;
        } else if (*protocol == "generate_content") {
            out.protocol = ProviderProtocol::GenerateContent;
        } else if (*protocol == "messages") {
            out.protocol = ProviderProtocol::Messages;
        } else if (*protocol == "local_cli") {
            out.protocol = ProviderProtocol::LocalCliText;
        } else {
            return fail(ConfigProblem::InvalidValue, "provider.protocol");
        }
    }
    if (out.protocol == ProviderProtocol::LocalCliText) {
        if (o.contains("url") || o.contains("credential_file") || o.contains("trust_file") ||
            o.contains("credential_rotation_origin") || o.contains("credential_mode") ||
            o.contains("api_version_header_name") || o.contains("api_version_header_value")) {
            return fail(ConfigProblem::InvalidValue, "provider.cli");
        }
        return parse_cli_config(o, at, out.cli);
    }
    if (o.contains("cli")) return fail(ConfigProblem::InvalidValue, "provider.cli");

    auto url = text(o, "url", at);
    auto credential = text(o, "credential_file", at);
    if (!url) return std::unexpected(url.error());
    if (!credential) return std::unexpected(credential.error());
    if (auto r = parse_provider_url(*url, out); !r) return r;
    out.credential_file = resolve(base, *credential);
    if (o.contains("trust_file")) {
        auto trust = text(o, "trust_file", at);
        if (!trust) return std::unexpected(trust.error());
        out.trust_file = resolve(base, *trust);
    }
    if (o.contains("credential_rotation_origin")) {
        auto origin = text(o, "credential_rotation_origin", at);
        if (!origin) return std::unexpected(origin.error());
        if (!valid_origin_name(*origin)) {
            return fail(ConfigProblem::InvalidValue, "provider.credential_rotation_origin");
        }
        out.credential_rotation_origin = std::move(*origin);
    }
    if (o.contains("credential_mode")) {
        auto mode = text(o, "credential_mode", at);
        if (!mode) return std::unexpected(mode.error());
        if (*mode == "bearer") {
            out.credential_mode = ProviderCredentialMode::Bearer;
        } else if (*mode == "api_key_header") {
            out.credential_mode = ProviderCredentialMode::ApiKeyHeader;
        } else {
            return fail(ConfigProblem::InvalidValue, "provider.credential_mode");
        }
    }
    if (out.credential_mode == ProviderCredentialMode::ApiKeyHeader &&
        out.protocol != ProviderProtocol::GenerateContent) {
        return fail(ConfigProblem::InvalidValue, "provider.credential_mode");
    }
    const bool has_version_name = o.contains("api_version_header_name");
    const bool has_version_value = o.contains("api_version_header_value");
    if (out.protocol == ProviderProtocol::Messages) {
        if (!has_version_name) return fail(ConfigProblem::Missing, "provider.api_version_header_name");
        if (!has_version_value) return fail(ConfigProblem::Missing, "provider.api_version_header_value");
        auto name = text(o, "api_version_header_name", at);
        auto value = text(o, "api_version_header_value", at);
        if (!name) return std::unexpected(name.error());
        if (!value) return std::unexpected(value.error());
        if (!name->ends_with("-version") || !valid_header_token(*name)) {
            return fail(ConfigProblem::InvalidValue, "provider.api_version_header_name");
        }
        if (!valid_api_version_date(*value)) {
            return fail(ConfigProblem::InvalidValue, "provider.api_version_header_value");
        }
        out.api_version_header_name = std::move(*name);
        out.api_version_header_value = std::move(*value);
    } else if (has_version_name || has_version_value) {
        return fail(ConfigProblem::InvalidValue, has_version_name ? "provider.api_version_header_name"
                                                                  : "provider.api_version_header_value");
    }
    return {};
}

Result parse_origins(const json& root, std::vector<Origin>& out) {
    auto node = member(root, "origins", "", json::value_t::array);
    if (!node) {
        return std::unexpected(node.error());
    }
    if ((*node)->empty()) {
        return fail(ConfigProblem::Missing, "origins");
    }
    std::set<std::string> names;
    std::set<std::string> hashes;
    for (std::size_t i = 0; i < (*node)->size(); ++i) {
        const std::string at = "origins[" + std::to_string(i) + "]";
        const json& o = (**node)[i];
        if (!o.is_object()) {
            return fail(ConfigProblem::WrongType, at);
        }
        if (auto r = only_keys(o, {"name", "token_sha256", "grade_policy"}, at); !r) {
            return r;
        }
        auto name = text(o, "name", at);
        auto hash_text = text(o, "token_sha256", at);
        auto policy_text = text(o, "grade_policy", at);
        if (!name) return std::unexpected(name.error());
        if (!hash_text) return std::unexpected(hash_text.error());
        if (!policy_text) return std::unexpected(policy_text.error());
        if (!valid_origin_name(*name)) {
            return fail(ConfigProblem::InvalidValue, at + ".name");
        }
        if (!lowercase_sha256_hex(*hash_text)) {
            return fail(ConfigProblem::InvalidValue, at + ".token_sha256");
        }
        core::GradePolicy policy{};
        if (*policy_text == "o-only") {
            policy = core::GradePolicy::OOnly;
        } else if (*policy_text == "declare") {
            policy = core::GradePolicy::Declare;
        } else {
            return fail(ConfigProblem::InvalidValue, at + ".grade_policy");
        }
        if (!names.insert(*name).second) {
            return fail(ConfigProblem::Duplicate, at + ".name");
        }
        if (!hashes.insert(*hash_text).second) {
            return fail(ConfigProblem::Duplicate, at + ".token_sha256");
        }
        out.push_back({std::move(*name), std::move(*hash_text), policy});
    }
    return {};
}

Result parse_terms(const json& root, std::vector<std::string>& out) {
    auto node = member(root, "internal_terms", "", json::value_t::array);
    if (!node) {
        return std::unexpected(node.error());
    }
    for (std::size_t i = 0; i < (*node)->size(); ++i) {
        const json& term = (**node)[i];
        const std::string at = "internal_terms[" + std::to_string(i) + "]";
        if (!term.is_string()) {
            return fail(ConfigProblem::WrongType, at);
        }
        if (term.get_ref<const std::string&>().empty()) {
            return fail(ConfigProblem::InvalidValue, at);
        }
        out.push_back(term.get<std::string>());
    }
    return {};
}

// policy.<key> 의 문자열 배열. 빈 값과 같은 값 두 번은 받지 않는다. 각 값은 check 로 바꾼다(실패면 InvalidValue).
template <class T, class F>
Result string_list(const json& policy, std::string_view key, std::size_t max_items, std::vector<T>& out, F check) {
    if (!policy.contains(key)) {
        return {};
    }
    const std::string at = "policy." + std::string(key);
    auto node = member(policy, key, "policy", json::value_t::array);
    if (!node) {
        return std::unexpected(node.error());
    }
    if ((*node)->size() > max_items) {
        return fail(ConfigProblem::InvalidValue, at);
    }
    std::set<std::string> seen;
    for (std::size_t i = 0; i < (*node)->size(); ++i) {
        const json& item = (**node)[i];
        const std::string field = at + "[" + std::to_string(i) + "]";
        if (!item.is_string()) {
            return fail(ConfigProblem::WrongType, field);
        }
        const auto& s = item.get_ref<const std::string&>();
        if (!seen.insert(s).second) {
            return fail(ConfigProblem::Duplicate, field);
        }
        auto value = s.empty() ? std::nullopt : check(s);
        if (!value) {
            return fail(ConfigProblem::InvalidValue, field);
        }
        out.push_back(std::move(*value));
    }
    return {};
}

// 기관 정책 묶음(ADR 0027). 없으면 업종 표지어도 기관 번호 규칙도 쓰지 않는다.
Result parse_policy(const json& root, detect::InstitutionPolicy& out) {
    if (!root.contains("policy")) {
        return {};
    }
    auto node = member(root, "policy", "", json::value_t::object);
    if (!node) {
        return std::unexpected(node.error());
    }
    const json& policy = **node;
    if (auto r = only_keys(
            policy, {"industries", "id_labels", "id_formats", "confidential_markers", "confidential_subjects"}, "policy");
        !r) {
        return r;
    }
    if (auto r = string_list(policy, "industries", detect::industry_count, out.industries,
                             [](const std::string& s) { return detect::industry_from_name(s); });
        !r) {
        return r;
    }
    // 글자 수(UTF-8 이어지는 byte 를 뺀 수). UTF-8 검증은 탐지기 조립이 한다.
    const auto short_term = [](const std::string& s) -> std::optional<std::string> {
        const auto chars = std::ranges::count_if(s, [](char c) { return (c & 0xC0) != 0x80; });
        return static_cast<std::size_t>(chars) <= detect::max_id_label_length ? std::optional(s) : std::nullopt;
    };
    if (auto r = string_list(policy, "id_labels", detect::max_id_labels, out.id_labels, short_term); !r) {
        return r;
    }
    if (auto r = string_list(policy, "confidential_markers", detect::max_confidential_terms, out.confidential_markers,
                             short_term);
        !r) {
        return r;
    }
    if (auto r = string_list(policy, "confidential_subjects", detect::max_confidential_terms,
                             out.confidential_subjects, short_term);
        !r) {
        return r;
    }
    return string_list(policy, "id_formats", detect::max_id_formats, out.id_formats,
                       [](const std::string& s) { return detect::IdFormat::parse(s); });
}

// 같은 객체 안의 중복 키를 찾는다. 라이브러리는 마지막 값을 조용히 쓰므로 직접 막는다.
class DuplicateKeyGuard {
public:
    bool operator()(int depth, json::parse_event_t event, const json& parsed) {
        const auto level = static_cast<std::size_t>(depth);
        if (event == json::parse_event_t::object_start) {
            if (keys_.size() <= level) {
                keys_.resize(level + 1);
            }
            keys_[level].clear();
        } else if (event == json::parse_event_t::key && level >= 1 && level <= keys_.size()) {
            if (!keys_[level - 1].insert(parsed.get<std::string>()).second) {
                duplicate_ = true;
            }
        }
        return true;
    }
    [[nodiscard]] bool found() const noexcept { return duplicate_; }

private:
    std::vector<std::set<std::string>> keys_;
    bool duplicate_ = false;
};

std::atomic<std::uint64_t> config_temp_sequence{0};

class ConfigMutationLock {
public:
    explicit ConfigMutationLock(const std::filesystem::path& file) {
#ifdef _WIN32
        std::error_code ec;
        const auto canonical = std::filesystem::canonical(file, ec);
        if (ec) return;
        const auto native = canonical.native();
        const int lower_size = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, native.c_str(), -1, nullptr, 0,
                                             nullptr, nullptr, 0);
        if (lower_size <= 0) return;
        std::wstring lower(static_cast<std::size_t>(lower_size), L'\0');
        if (LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, native.c_str(), -1, lower.data(), lower_size,
                          nullptr, nullptr, 0) == 0) {
            return;
        }
        lower.resize(static_cast<std::size_t>(lower_size - 1));
        const auto path_bytes = std::as_bytes(std::span(lower.data(), lower.size()));
        const auto digest = prompt_airlock::core::sha256_hex(path_bytes);
        std::wstring object_name = L"Global\\PromptAirlock.Keys.";
        object_name.append(digest.begin(), digest.end());
        mutex_ = CreateMutexW(nullptr, FALSE, object_name.c_str());
        if (!mutex_) return;
        const DWORD wait = WaitForSingleObject(mutex_, INFINITE);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
            locked_ = true;
        }
#else
        auto directory = file.parent_path();
        if (directory.empty()) directory = ".";
        int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_DIRECTORY
        flags |= O_DIRECTORY;
#endif
        descriptor_ = ::open(directory.c_str(), flags);
        if (descriptor_ < 0) return;
        while (::flock(descriptor_, LOCK_EX) != 0) {
            if (errno != EINTR) return;
        }
        locked_ = true;
#endif
    }

    ConfigMutationLock(const ConfigMutationLock&) = delete;
    ConfigMutationLock& operator=(const ConfigMutationLock&) = delete;

    ~ConfigMutationLock() {
#ifdef _WIN32
        if (locked_) (void)ReleaseMutex(mutex_);
        if (mutex_) (void)CloseHandle(mutex_);
#else
        if (descriptor_ >= 0) {
            if (locked_) (void)::flock(descriptor_, LOCK_UN);
            (void)::close(descriptor_);
        }
#endif
    }

    [[nodiscard]] bool locked() const noexcept { return locked_; }

private:
#ifdef _WIN32
    HANDLE mutex_ = nullptr;
#else
    int descriptor_ = -1;
#endif
    bool locked_ = false;
};

std::expected<std::string, OriginFileError> read_config_text(const std::filesystem::path& file) {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(file, ec);
    if (ec) return std::unexpected(OriginFileError::ReadFailed);
    if (!std::filesystem::is_regular_file(status)) return std::unexpected(OriginFileError::UnsafePermissions);
    std::ifstream input(file, std::ios::binary);
    if (!input) return std::unexpected(OriginFileError::ReadFailed);
    std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    if (input.bad()) return std::unexpected(OriginFileError::ReadFailed);
    return text;
}

std::string temp_suffix() {
#ifdef _WIN32
    const auto process = static_cast<std::uint64_t>(GetCurrentProcessId());
#else
    const auto process = static_cast<std::uint64_t>(::getpid());
#endif
    return ".keys." + std::to_string(process) + "." +
           std::to_string(config_temp_sequence.fetch_add(1, std::memory_order_relaxed));
}

#ifdef _WIN32
struct DaclSnapshot {
    std::vector<std::byte> descriptor;
    std::vector<std::byte> acl;
    std::vector<std::byte> owner_sid;
    std::vector<std::byte> group_sid;
    PACL value = nullptr;
    PSID owner = nullptr;
    PSID group = nullptr;
    SECURITY_DESCRIPTOR_CONTROL control = 0;
};

std::expected<DaclSnapshot, OriginFileError> read_dacl(const std::filesystem::path& file) {
    DWORD needed = 0;
    constexpr SECURITY_INFORMATION requested = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                               DACL_SECURITY_INFORMATION;
    (void)GetFileSecurityW(file.c_str(), requested, nullptr, 0, &needed);
    if (needed == 0) return std::unexpected(OriginFileError::UnsafePermissions);
    DaclSnapshot snapshot;
    snapshot.descriptor.resize(needed);
    if (!GetFileSecurityW(file.c_str(), requested,
                          reinterpret_cast<PSECURITY_DESCRIPTOR>(snapshot.descriptor.data()), needed, &needed)) {
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    PSID owner = nullptr;
    PSID group = nullptr;
    BOOL owner_defaulted = FALSE;
    BOOL group_defaulted = FALSE;
    if (!GetSecurityDescriptorOwner(reinterpret_cast<PSECURITY_DESCRIPTOR>(snapshot.descriptor.data()), &owner,
                                    &owner_defaulted) ||
        !GetSecurityDescriptorGroup(reinterpret_cast<PSECURITY_DESCRIPTOR>(snapshot.descriptor.data()), &group,
                                    &group_defaulted) ||
        !owner || !group || !IsValidSid(owner) || !IsValidSid(group)) {
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    const DWORD owner_size = GetLengthSid(owner);
    const DWORD group_size = GetLengthSid(group);
    if (owner_size == 0 || group_size == 0) return std::unexpected(OriginFileError::UnsafePermissions);
    snapshot.owner_sid.resize(owner_size);
    snapshot.group_sid.resize(group_size);
    if (!CopySid(owner_size, snapshot.owner_sid.data(), owner) ||
        !CopySid(group_size, snapshot.group_sid.data(), group)) {
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    snapshot.owner = snapshot.owner_sid.data();
    snapshot.group = snapshot.group_sid.data();
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(reinterpret_cast<PSECURITY_DESCRIPTOR>(snapshot.descriptor.data()),
                                      &snapshot.control, &revision)) {
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL acl = nullptr;
    if (!GetSecurityDescriptorDacl(reinterpret_cast<PSECURITY_DESCRIPTOR>(snapshot.descriptor.data()), &present, &acl,
                                   &defaulted) ||
        !present || !acl) {
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    snapshot.acl.resize(acl->AclSize);
    std::memcpy(snapshot.acl.data(), acl, acl->AclSize);
    snapshot.value = reinterpret_cast<PACL>(snapshot.acl.data());
    return snapshot;
}

bool same_file_security(const std::filesystem::path& file, const DaclSnapshot& expected) {
    const auto current = read_dacl(file);
    constexpr SECURITY_DESCRIPTOR_CONTROL relevant_control = SE_OWNER_DEFAULTED | SE_GROUP_DEFAULTED | SE_DACL_DEFAULTED |
                                                              SE_DACL_AUTO_INHERIT_REQ | SE_DACL_AUTO_INHERITED |
                                                              SE_DACL_PROTECTED;
    return current && current->owner_sid == expected.owner_sid && current->group_sid == expected.group_sid &&
           current->acl == expected.acl &&
           (current->control & relevant_control) == (expected.control & relevant_control);
}

bool windows_file_exists(const std::filesystem::path& file) {
    const DWORD attributes = GetFileAttributesW(file.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool restore_windows_backup(const std::filesystem::path& target, const std::filesystem::path& backup) {
    if (!windows_file_exists(backup)) return windows_file_exists(target);
    if (windows_file_exists(target)) {
        auto rollback = target;
        rollback += temp_suffix() + ".rollback";
        if (!ReplaceFileW(target.c_str(), backup.c_str(), rollback.c_str(), 0, nullptr, nullptr)) return false;
        return DeleteFileW(rollback.c_str()) != 0;
    }
    return MoveFileExW(backup.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
}

std::expected<void, OriginFileError> replace_config_atomically(const std::filesystem::path& target,
                                                               std::string_view content) {
    const DWORD attributes = GetFileAttributesW(target.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || (attributes & FILE_ATTRIBUTE_ENCRYPTED) != 0) {
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    auto dacl = read_dacl(target);
    if (!dacl) return std::unexpected(dacl.error());

    std::filesystem::path temp;
    HANDLE output = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt < 32 && output == INVALID_HANDLE_VALUE; ++attempt) {
        temp = target;
        temp += temp_suffix() + ".tmp." + std::to_string(attempt);
        output = CreateFileW(temp.c_str(), GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, 0, nullptr, CREATE_NEW,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
        if (output == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_EXISTS &&
            GetLastError() != ERROR_ALREADY_EXISTS) {
            return std::unexpected(OriginFileError::WriteFailed);
        }
    }
    if (output == INVALID_HANDLE_VALUE) return std::unexpected(OriginFileError::WriteFailed);

    SECURITY_INFORMATION security = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    security |= (dacl->control & SE_DACL_PROTECTED) != 0 ? PROTECTED_DACL_SECURITY_INFORMATION
                                                         : UNPROTECTED_DACL_SECURITY_INFORMATION;
    bool written = SetSecurityInfo(output, SE_FILE_OBJECT, security, dacl->owner, dacl->group, dacl->value, nullptr) ==
                   ERROR_SUCCESS;
    std::size_t offset = 0;
    while (written && offset < content.size()) {
        const auto remaining = content.size() - offset;
        const DWORD chunk = remaining > std::numeric_limits<DWORD>::max()
            ? std::numeric_limits<DWORD>::max() : static_cast<DWORD>(remaining);
        DWORD count = 0;
        written = WriteFile(output, content.data() + offset, chunk, &count, nullptr) != 0 && count != 0;
        offset += count;
    }
    if (written) written = FlushFileBuffers(output) != 0;
    const bool closed = CloseHandle(output) != 0;
    written = written && closed;
    if (!written) {
        (void)DeleteFileW(temp.c_str());
        return std::unexpected(OriginFileError::WriteFailed);
    }

    auto backup = target;
    backup += temp_suffix() + ".backup";
    if (!ReplaceFileW(target.c_str(), temp.c_str(), backup.c_str(), 0, nullptr, nullptr)) {
        const bool restored = restore_windows_backup(target, backup);
        (void)DeleteFileW(temp.c_str());
        return std::unexpected(restored ? OriginFileError::WriteFailed : OriginFileError::UnsafePermissions);
    }

    const auto readback = read_config_text(target);
    if (!readback || *readback != content || !same_file_security(target, *dacl)) {
        const bool restored = restore_windows_backup(target, backup);
        return std::unexpected(restored ? OriginFileError::WriteFailed : OriginFileError::UnsafePermissions);
    }
    if (!DeleteFileW(backup.c_str())) {
        const bool restored = restore_windows_backup(target, backup);
        return std::unexpected(restored ? OriginFileError::WriteFailed : OriginFileError::UnsafePermissions);
    }
    return {};
}
#else
using Xattr = std::pair<std::string, std::vector<unsigned char>>;

std::expected<std::vector<Xattr>, OriginFileError> read_xattrs(int descriptor) {
    const ssize_t size = ::flistxattr(descriptor, nullptr, 0);
    if (size < 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP) return std::vector<Xattr>{};
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    std::vector<char> names(static_cast<std::size_t>(size));
    if (size > 0 && ::flistxattr(descriptor, names.data(), names.size()) != size) {
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    std::vector<Xattr> values;
    for (std::size_t offset = 0; offset < names.size();) {
        const std::string name(names.data() + offset);
        offset += name.size() + 1;
        if (name == "security.ima" || name == "security.evm") {
            return std::unexpected(OriginFileError::UnsafePermissions);
        }
        const ssize_t value_size = ::fgetxattr(descriptor, name.c_str(), nullptr, 0);
        if (value_size < 0) return std::unexpected(OriginFileError::UnsafePermissions);
        std::vector<unsigned char> value(static_cast<std::size_t>(value_size));
        if (value_size > 0 && ::fgetxattr(descriptor, name.c_str(), value.data(), value.size()) != value_size) {
            return std::unexpected(OriginFileError::UnsafePermissions);
        }
        values.emplace_back(name, std::move(value));
    }
    return values;
}

bool same_xattr_names(const std::vector<Xattr>& expected, const std::vector<Xattr>& current) {
    if (expected.size() != current.size()) return false;
    return std::ranges::all_of(expected, [&](const Xattr& item) {
        return std::ranges::any_of(current, [&](const Xattr& candidate) {
            return item.first == candidate.first && item.second == candidate.second;
        });
    });
}

std::expected<void, OriginFileError> replace_config_atomically(const std::filesystem::path& target,
                                                               std::string_view content) {
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int source = ::open(target.c_str(), flags);
    if (source < 0) return std::unexpected(OriginFileError::UnsafePermissions);
    struct stat original {};
    if (::fstat(source, &original) != 0 || !S_ISREG(original.st_mode) || original.st_nlink != 1) {
        (void)::close(source);
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    const auto xattrs = read_xattrs(source);
    if (!xattrs) {
        (void)::close(source);
        return std::unexpected(xattrs.error());
    }

    std::filesystem::path temp;
    int output = -1;
    for (unsigned attempt = 0; attempt < 32 && output < 0; ++attempt) {
        temp = target;
        temp += temp_suffix() + ".tmp." + std::to_string(attempt);
        output = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC
#ifdef O_NOFOLLOW
                        | O_NOFOLLOW
#endif
                        , 0600);
        if (output < 0 && errno != EEXIST) {
            (void)::close(source);
            return std::unexpected(OriginFileError::WriteFailed);
        }
    }
    if (output < 0) {
        (void)::close(source);
        return std::unexpected(OriginFileError::WriteFailed);
    }

    bool written = ::fchown(output, original.st_uid, original.st_gid) == 0 &&
                   ::fchmod(output, original.st_mode & 07777) == 0;
    const auto current_xattrs = read_xattrs(output);
    if (!current_xattrs) written = false;
    if (written) {
        for (const auto& current : *current_xattrs) {
            if (std::ranges::none_of(*xattrs, [&](const Xattr& expected) { return expected.first == current.first; }) &&
                ::fremovexattr(output, current.first.c_str()) != 0) {
                written = false;
                break;
            }
        }
    }
    for (const auto& [name, value] : *xattrs) {
        if (!written) break;
        if (::fsetxattr(output, name.c_str(), value.data(), value.size(), 0) != 0) written = false;
    }
    std::size_t offset = 0;
    while (written && offset < content.size()) {
        const auto count = ::write(output, content.data() + offset, content.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            written = false;
            break;
        }
        offset += static_cast<std::size_t>(count);
    }
    if (written) written = ::fsync(output) == 0;
    const bool closed = ::close(output) == 0;
    written = written && closed;
    (void)::close(source);
    if (!written) {
        (void)::unlink(temp.c_str());
        return std::unexpected(OriginFileError::WriteFailed);
    }

    std::filesystem::path backup;
    bool linked = false;
    for (unsigned attempt = 0; attempt < 32 && !linked; ++attempt) {
        backup = target;
        backup += temp_suffix() + ".backup." + std::to_string(attempt);
        if (::link(target.c_str(), backup.c_str()) == 0) {
            linked = true;
        } else if (errno != EEXIST) {
            break;
        }
    }
    struct stat backed_up {};
    if (!linked || ::stat(backup.c_str(), &backed_up) != 0 || backed_up.st_dev != original.st_dev ||
        backed_up.st_ino != original.st_ino) {
        if (linked) (void)::unlink(backup.c_str());
        (void)::unlink(temp.c_str());
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    if (::rename(temp.c_str(), target.c_str()) != 0) {
        const bool backup_removed = ::unlink(backup.c_str()) == 0;
        (void)::unlink(temp.c_str());
        return std::unexpected(backup_removed ? OriginFileError::WriteFailed : OriginFileError::UnsafePermissions);
    }
    const int committed = ::open(target.c_str(), O_RDONLY | O_CLOEXEC
#ifdef O_NOFOLLOW
                                 | O_NOFOLLOW
#endif
                                 );
    if (committed < 0) {
        if (::rename(backup.c_str(), target.c_str()) == 0) return std::unexpected(OriginFileError::WriteFailed);
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    struct stat updated {};
    const auto updated_xattrs = read_xattrs(committed);
    const bool verified = ::fstat(committed, &updated) == 0 && S_ISREG(updated.st_mode) &&
                          (updated.st_mode & 07777) == (original.st_mode & 07777) &&
                          updated.st_uid == original.st_uid && updated.st_gid == original.st_gid && updated_xattrs &&
                          same_xattr_names(*xattrs, *updated_xattrs);
    (void)::close(committed);
    if (!verified) {
        if (::rename(backup.c_str(), target.c_str()) == 0) return std::unexpected(OriginFileError::WriteFailed);
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    if (::unlink(backup.c_str()) != 0) {
        if (::rename(backup.c_str(), target.c_str()) == 0) return std::unexpected(OriginFileError::WriteFailed);
        return std::unexpected(OriginFileError::UnsafePermissions);
    }
    return {};
}
#endif

}  // namespace

std::expected<Config, ConfigError> parse_config(std::string_view json_text, const std::filesystem::path& base_dir) {
    DuplicateKeyGuard guard;
    const json root = json::parse(json_text, std::ref(guard), /*allow_exceptions=*/false);
    if (root.is_discarded() || !root.is_object()) {
        return fail(ConfigProblem::NotJson, "");
    }
    if (guard.found()) {
        return fail(ConfigProblem::Duplicate, "");
    }
    if (auto r = only_keys(root, {"listen", "provider", "origins", "admin_history_origin", "internal_terms", "policy",
                                  "output_token_cap", "history_retention_days", "sentence_warn", "compat"}, ""); !r) {
        return std::unexpected(r.error());
    }
    Config config;
    if (auto r = parse_listen(root, base_dir, config.listen); !r) return std::unexpected(r.error());
    if (auto r = parse_provider(root, base_dir, config.provider); !r) return std::unexpected(r.error());
    if (auto r = parse_origins(root, config.origins); !r) return std::unexpected(r.error());
    if (!config.provider.credential_rotation_origin.empty() &&
        std::ranges::none_of(config.origins, [&](const Origin& origin) {
            return origin.name == config.provider.credential_rotation_origin;
        })) {
        return fail(ConfigProblem::InvalidValue, "provider.credential_rotation_origin");
    }
    if (root.contains("admin_history_origin")) {
        auto admin = member(root, "admin_history_origin", "", json::value_t::string);
        if (!admin) return std::unexpected(admin.error());
        const auto& admin_name = (*admin)->get_ref<const std::string&>();
        if (!valid_origin_name(admin_name)) return fail(ConfigProblem::InvalidValue, "admin_history_origin");
        const auto registered = std::ranges::find(config.origins, admin_name, &Origin::name);
        if (registered == config.origins.end() || admin_name == config.provider.credential_rotation_origin) {
            return fail(ConfigProblem::InvalidValue, "admin_history_origin");
        }
        config.admin_history_origin = admin_name;
    }
    if (auto r = parse_terms(root, config.internal_terms); !r) return std::unexpected(r.error());
    if (auto r = parse_policy(root, config.policy); !r) return std::unexpected(r.error());
    if (root.contains("output_token_cap")) {
        auto value = member(root, "output_token_cap", "", json::value_t::number_unsigned);
        if (!value) {
            return std::unexpected(value.error());
        }
        const auto n = (*value)->get<std::int64_t>();
        if (n < 1 || n > core::OutputTokenCap::max_value) {
            return fail(ConfigProblem::InvalidValue, "output_token_cap");
        }
        config.output_token_cap = *core::OutputTokenCap::make(static_cast<std::uint32_t>(n));
    }
    if (root.contains("history_retention_days")) {
        auto value = member(root, "history_retention_days", "", json::value_t::number_unsigned);
        if (!value) {
            return std::unexpected(value.error());
        }
        const auto n = (*value)->get<std::int64_t>();
        if (n < 365 || n > 36500) {
            return fail(ConfigProblem::InvalidValue, "history_retention_days");
        }
        config.history_retention_days = static_cast<int>(n);
    }
    if (root.contains("sentence_warn")) {
        auto value = member(root, "sentence_warn", "", json::value_t::boolean);
        if (!value) {
            return std::unexpected(value.error());
        }
        config.sentence_warn = (*value)->get<bool>();
    }
    if (root.contains("compat")) {
        auto node = member(root, "compat", "", json::value_t::object);
        if (!node) return std::unexpected(node.error());
        if (auto checked = only_keys(**node, {"chat_app"}, "compat"); !checked) return std::unexpected(checked.error());
        auto enabled = member(**node, "chat_app", "compat", json::value_t::boolean);
        if (!enabled) return std::unexpected(enabled.error());
        config.compat.chat_app = (*enabled)->get<bool>();
        if (config.compat.chat_app && config.listen.address != "127.0.0.1" && config.listen.address != "0.0.0.0") {
            return fail(ConfigProblem::InvalidValue, "compat.chat_app");
        }
    }
    return config;
}

std::string_view config_problem_name(ConfigProblem problem) noexcept {
    switch (problem) {
        case ConfigProblem::NotJson: return "not_json";
        case ConfigProblem::UnknownKey: return "unknown_key";
        case ConfigProblem::Missing: return "missing";
        case ConfigProblem::WrongType: return "wrong_type";
        case ConfigProblem::InvalidValue: return "invalid_value";
        case ConfigProblem::Duplicate: return "duplicate";
    }
    return "unknown";
}

std::string_view origin_file_error_name(OriginFileError error) noexcept {
    switch (error) {
        case OriginFileError::InvalidName: return "invalid_name";
        case OriginFileError::InvalidConfig: return "invalid_config";
        case OriginFileError::InvalidCandidateConfig: return "invalid_candidate_config";
        case OriginFileError::ReadFailed: return "read_failed";
        case OriginFileError::Duplicate: return "duplicate";
        case OriginFileError::NotFound: return "not_found";
        case OriginFileError::InUse: return "origin_in_use";
        case OriginFileError::LastOrigin: return "last_origin";
        case OriginFileError::LockFailed: return "lock_failed";
        case OriginFileError::UnsafePermissions: return "unsafe_permissions";
        case OriginFileError::WriteFailed: return "write_failed";
    }
    return "invalid_config";
}

std::expected<std::vector<Origin>, OriginFileError> manage_origin_file(const std::filesystem::path& file,
                                                                       OriginFileAction action,
                                                                       std::string_view name,
                                                                       std::string_view token_sha256,
                                                                       core::GradePolicy grade_policy) {
    try {
        if (action != OriginFileAction::List && !valid_origin_name(name)) {
            return std::unexpected(OriginFileError::InvalidName);
        }
        std::optional<ConfigMutationLock> lock;
        if (action != OriginFileAction::List) {
            lock.emplace(file);
            if (!lock->locked()) return std::unexpected(OriginFileError::LockFailed);
        }

        const auto source = read_config_text(file);
        if (!source) return std::unexpected(source.error());
        const auto base_dir = file.parent_path().empty() ? std::filesystem::path(".") : file.parent_path();
        const auto current = parse_config(*source, base_dir);
        if (!current) {
            return std::unexpected(current.error().problem == ConfigProblem::Duplicate ? OriginFileError::Duplicate
                                                                                      : OriginFileError::InvalidConfig);
        }
        if (action == OriginFileAction::List) return current->origins;
        if (action != OriginFileAction::Add && action != OriginFileAction::Revoke) {
            return std::unexpected(OriginFileError::InvalidConfig);
        }

        DuplicateKeyGuard guard;
        json root = json::parse(*source, std::ref(guard), /*allow_exceptions=*/false);
        if (root.is_discarded() || guard.found()) return std::unexpected(OriginFileError::InvalidConfig);
        auto& origins = root["origins"];
        if (action == OriginFileAction::Add) {
            if (grade_policy != core::GradePolicy::OOnly && grade_policy != core::GradePolicy::Declare) {
                return std::unexpected(OriginFileError::InvalidConfig);
            }
            if (std::ranges::any_of(current->origins, [&](const Origin& origin) {
                    return origin.name == name || origin.token_sha256 == token_sha256;
                })) {
                return std::unexpected(OriginFileError::Duplicate);
            }
            origins.push_back({{"name", name},
                               {"token_sha256", token_sha256},
                               {"grade_policy", grade_policy == core::GradePolicy::OOnly ? "o-only" : "declare"}});
        } else {
            const auto found = std::ranges::find_if(origins, [&](const json& origin) {
                return origin["name"].get_ref<const std::string&>() == name;
            });
            if (found == origins.end()) return std::unexpected(OriginFileError::NotFound);
            if (origins.size() == 1) return std::unexpected(OriginFileError::LastOrigin);
            const auto& provider = root["provider"];
            if ((provider.contains("credential_rotation_origin") &&
                 provider["credential_rotation_origin"].get_ref<const std::string&>() == name) ||
                (root.contains("admin_history_origin") &&
                 root["admin_history_origin"].get_ref<const std::string&>() == name)) {
                return std::unexpected(OriginFileError::InUse);
            }
            origins.erase(found);
        }

        const auto serialized = root.dump(2) + "\n";
        const auto updated = parse_config(serialized, base_dir);
        if (!updated) {
            return std::unexpected(updated.error().problem == ConfigProblem::Duplicate ? OriginFileError::Duplicate
                                                                                      : OriginFileError::InvalidCandidateConfig);
        }
        const auto replacement_result = replace_config_atomically(file, serialized);
        if (!replacement_result) return std::unexpected(replacement_result.error());
        return updated->origins;
    } catch (...) {
        return std::unexpected(OriginFileError::WriteFailed);
    }
}

}  // namespace prompt_airlock::gateway
