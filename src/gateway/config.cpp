#include "prompt_airlock/gateway/config.hpp"

#include <boost/asio/ip/address.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <functional>
#include <initializer_list>
#include <set>
#include <utility>

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
    if (auto r = only_keys(o, {"url", "credential_file", "trust_file", "model"}, at); !r) {
        return r;
    }
    auto url = text(o, "url", at);
    auto credential = text(o, "credential_file", at);
    auto model = text(o, "model", at);
    if (!url) return std::unexpected(url.error());
    if (!credential) return std::unexpected(credential.error());
    if (!model) return std::unexpected(model.error());
    if (auto r = parse_provider_url(*url, out); !r) {
        return r;
    }
    if (model->size() > 128 || !printable_ascii(*model)) {
        return fail(ConfigProblem::InvalidValue, "provider.model");
    }
    out.credential_file = resolve(base, *credential);
    out.model = std::move(*model);
    if (o.contains("trust_file")) {
        auto trust = text(o, "trust_file", at);
        if (!trust) return std::unexpected(trust.error());
        out.trust_file = resolve(base, *trust);
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
    if (auto r = only_keys(root, {"listen", "provider", "origins", "internal_terms", "output_token_cap"}, ""); !r) {
        return std::unexpected(r.error());
    }
    Config config;
    if (auto r = parse_listen(root, base_dir, config.listen); !r) return std::unexpected(r.error());
    if (auto r = parse_provider(root, base_dir, config.provider); !r) return std::unexpected(r.error());
    if (auto r = parse_origins(root, config.origins); !r) return std::unexpected(r.error());
    if (auto r = parse_terms(root, config.internal_terms); !r) return std::unexpected(r.error());
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

}  // namespace prompt_airlock::gateway
