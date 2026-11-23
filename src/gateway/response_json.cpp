#include "prompt_airlock/gateway/response_json.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <limits>
#include <random>
#include <set>
#include <utility>
#include <vector>

#include "prompt_airlock/gateway/request_json.hpp"
#include "role_name.hpp"

namespace prompt_airlock::gateway {
namespace {

using json = nlohmann::json;

constexpr std::array<std::string_view, 5> forbidden_keys = {"tool_calls", "function_call", "audio", "images",
                                                            "logprobs"};

// 위치를 따라가며 선택한 규격의 허용 응답 필드만 꺼내는 SAX 핸들러.
class AnswerSax {
public:
    explicit AnswerSax(ProviderProtocol protocol) : protocol_(protocol) {}

    std::optional<AnswerError> failure;
    std::optional<core::SensitiveText> content;
    std::optional<std::string> role;
    std::string finish_reason;
    Usage usage;
    bool has_usage = false;
    std::size_t candidate_count = 0;
    std::size_t part_count = 0;
    bool has_content_type = false;

    bool null() {
        if (protocol_ == ProviderProtocol::ChatCompletions) {
            step();
            return true;
        }
        return value();
    }
    bool boolean(bool) { return value(); }
    bool number_integer(json::number_integer_t v) { return integer(v); }
    bool number_unsigned(json::number_unsigned_t v) {
        return integer(v > static_cast<json::number_unsigned_t>(std::numeric_limits<std::int64_t>::max()) ? -1 : static_cast<std::int64_t>(v));
    }
    bool number_float(json::number_float_t, const std::string&) { return value(); }
    bool binary(json::binary_t&) { return fail(AnswerError::Malformed); }

    bool string(std::string& v) {
        if (!value(true)) {
            return false;
        }
        if (protocol_ == ProviderProtocol::ChatCompletions && at({"choices", "0", "message", "content"})) {
            content = core::SensitiveText(std::move(v));
        } else if (protocol_ == ProviderProtocol::ChatCompletions && at({"choices", "0", "message", "role"})) {
            role = v;
        } else if (protocol_ == ProviderProtocol::ChatCompletions && at({"choices", "0", "finish_reason"})) {
            finish_reason = v;
        } else if (protocol_ == ProviderProtocol::GenerateContent && at({"candidates", "0", "content", "role"})) {
            role = v;
        } else if (protocol_ == ProviderProtocol::GenerateContent &&
                   at({"candidates", "0", "content", "parts", "0", "text"})) {
            content = core::SensitiveText(std::move(v));
        } else if (protocol_ == ProviderProtocol::GenerateContent && at({"candidates", "0", "finishReason"})) {
            finish_reason = v;
        } else if (protocol_ == ProviderProtocol::Messages && at({"role"})) {
            role = v;
        } else if (protocol_ == ProviderProtocol::Messages && at({"content", "0", "type"})) {
            has_content_type = true;
            if (v != "text") return fail(AnswerError::Forbidden);
        } else if (protocol_ == ProviderProtocol::Messages && at({"content", "0", "text"})) {
            content = core::SensitiveText(std::move(v));
        } else if (protocol_ == ProviderProtocol::Messages && at({"stop_reason"})) {
            finish_reason = v;
        }
        return true;
    }

    bool start_object(std::size_t) { return open(false); }
    bool start_array(std::size_t) { return open(true); }
    bool end_object() { return close(); }
    bool end_array() { return close(); }

    bool key(std::string& name) {
        Level& top = stack_.back();
        if (!top.seen.insert(name).second) {
            return fail(AnswerError::Malformed);
        }
        const bool generate_part = protocol_ == ProviderProtocol::GenerateContent &&
                                   parent_at({"candidates", "0", "content", "parts", "0"});
        const bool message_part = protocol_ == ProviderProtocol::Messages && parent_at({"content", "0"});
        top.key = name;
        if (generate_part && name != "text") return fail(AnswerError::Forbidden);
        if (message_part && name != "type" && name != "text") return fail(AnswerError::Forbidden);
        return true;
    }

    bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) {
        return fail(AnswerError::Malformed);
    }

private:
    struct Level {
        bool array;
        std::string key;
        long index = -1;
        std::set<std::string, std::less<>> seen;
    };

    bool fail(AnswerError error) {
        if (!failure) {
            failure = error;
        }
        return false;
    }

    // 배열 안에서는 값마다 순번을 하나 올린다.
    void step() {
        if (!stack_.empty() && stack_.back().array) {
            ++stack_.back().index;
        }
    }

    [[nodiscard]] bool at(std::initializer_list<std::string_view> path) const {
        if (path.size() != stack_.size()) {
            return false;
        }
        auto it = path.begin();
        for (const Level& level : stack_) {
            const std::string part = level.array ? std::to_string(level.index) : level.key;
            if (part != *it++) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool parent_at(std::initializer_list<std::string_view> path) const {
        if (path.size() + 1 != stack_.size()) return false;
        auto it = path.begin();
        for (std::size_t i = 0; i + 1 < stack_.size(); ++i) {
            const Level& level = stack_[i];
            const std::string part = level.array ? std::to_string(level.index) : level.key;
            if (part != *it++) return false;
        }
        return true;
    }

    [[nodiscard]] bool in_array(std::initializer_list<std::string_view> path) const {
        return !stack_.empty() && stack_.back().array && parent_at(path);
    }

    [[nodiscard]] bool is_usage_value() const {
        return (protocol_ == ProviderProtocol::ChatCompletions &&
                (at({"usage", "prompt_tokens"}) || at({"usage", "completion_tokens"}) ||
                 at({"usage", "total_tokens"}))) ||
               (protocol_ == ProviderProtocol::GenerateContent &&
                (at({"usageMetadata", "promptTokenCount"}) || at({"usageMetadata", "candidatesTokenCount"}) ||
                 at({"usageMetadata", "totalTokenCount"}))) ||
               (protocol_ == ProviderProtocol::Messages &&
                (at({"usage", "input_tokens"}) || at({"usage", "output_tokens"}) ||
                 at({"usage", "total_tokens"})));
    }

    // choices 아래에서 금지 키가 값을 가지면 거절한다(null 은 위에서 통과).
    [[nodiscard]] bool forbidden_here() const {
        if (stack_.size() < 2 || stack_.front().key != "choices" || stack_.back().array) {
            return false;
        }
        return std::ranges::find(forbidden_keys, stack_.back().key) != forbidden_keys.end();
    }

    bool accept_value(bool string_value = false) {
        step();
        if (forbidden_here()) return fail(AnswerError::Forbidden);
        if (protocol_ == ProviderProtocol::Messages && !string_value && at({"content", "0", "type"})) {
            return fail(AnswerError::Forbidden);
        }
        return true;
    }

    bool value(bool string_value = false) {
        const bool candidate = protocol_ == ProviderProtocol::GenerateContent && in_array({"candidates"});
        const bool generated_part = protocol_ == ProviderProtocol::GenerateContent &&
                                    in_array({"candidates", "0", "content", "parts"});
        const bool message_part = protocol_ == ProviderProtocol::Messages && in_array({"content"});
        if (!accept_value(string_value)) return false;
        return candidate || generated_part || message_part ? fail(AnswerError::Forbidden) : true;
    }

    bool integer(std::int64_t v) {
        if (!value()) {
            return false;
        }
        if (protocol_ != ProviderProtocol::ChatCompletions && is_usage_value() && v < 0) {
            return fail(AnswerError::Malformed);
        }
        if (protocol_ == ProviderProtocol::ChatCompletions && at({"usage", "prompt_tokens"})) {
            usage.prompt_tokens = v;
            has_usage = true;
        } else if (protocol_ == ProviderProtocol::ChatCompletions && at({"usage", "completion_tokens"})) {
            usage.completion_tokens = v;
            has_usage = true;
        } else if (protocol_ == ProviderProtocol::ChatCompletions && at({"usage", "total_tokens"})) {
            usage.total_tokens = v;
            has_usage = true;
        } else if (protocol_ == ProviderProtocol::GenerateContent && at({"usageMetadata", "promptTokenCount"})) {
            usage.prompt_tokens = v;
            has_usage = true;
        } else if (protocol_ == ProviderProtocol::GenerateContent &&
                   at({"usageMetadata", "candidatesTokenCount"})) {
            usage.completion_tokens = v;
            has_usage = true;
        } else if (protocol_ == ProviderProtocol::GenerateContent && at({"usageMetadata", "totalTokenCount"})) {
            usage.total_tokens = v;
            has_usage = true;
        } else if (protocol_ == ProviderProtocol::Messages && at({"usage", "input_tokens"})) {
            usage.prompt_tokens = v;
            has_usage = true;
        } else if (protocol_ == ProviderProtocol::Messages && at({"usage", "output_tokens"})) {
            usage.completion_tokens = v;
            has_usage = true;
        } else if (protocol_ == ProviderProtocol::Messages && at({"usage", "total_tokens"})) {
            usage.total_tokens = v;
            has_usage = true;
        }
        return true;
    }

    bool open(bool array) {
        const bool candidate = protocol_ == ProviderProtocol::GenerateContent && in_array({"candidates"});
        const bool generated_part = protocol_ == ProviderProtocol::GenerateContent &&
                                    in_array({"candidates", "0", "content", "parts"});
        const bool message_part = protocol_ == ProviderProtocol::Messages && in_array({"content"});
        if (!stack_.empty() && !accept_value()) return false;
        if ((candidate || generated_part || message_part) && array) return fail(AnswerError::Forbidden);
        if (candidate && ++candidate_count > 1) return fail(AnswerError::Forbidden);
        if ((generated_part || message_part) && ++part_count > 1) return fail(AnswerError::Forbidden);
        if (stack_.empty() && array) {
            return fail(AnswerError::Malformed);
        }
        if (stack_.size() >= max_json_depth) {
            return fail(AnswerError::Malformed);
        }
        stack_.push_back({array, {}, -1, {}});
        return true;
    }

    bool close() {
        stack_.pop_back();
        return true;
    }

    std::vector<Level> stack_;
    ProviderProtocol protocol_;
};

// 규격 고유 종료 상태는 클라이언트가 이미 받는 호환 코드로만 바꾼다.
std::optional<std::string> clean_finish_reason(ProviderProtocol protocol, std::string_view reason) {
    if (protocol == ProviderProtocol::ChatCompletions) {
        const bool ok = !reason.empty() && reason.size() <= 32 &&
                        std::ranges::all_of(reason, [](char c) { return (c >= 'a' && c <= 'z') || c == '_'; });
        return ok ? std::optional<std::string>(reason) : std::optional<std::string>("stop");
    }
    if (reason.empty()) return "stop";
    if (protocol == ProviderProtocol::GenerateContent) {
        if (reason == "STOP") return "stop";
        if (reason == "MAX_TOKENS") return "length";
    } else {
        if (reason == "end_turn" || reason == "stop_sequence") return "stop";
        if (reason == "max_tokens") return "length";
    }
    return std::nullopt;
}

}  // namespace

// provider가 정한 ID 대신 게이트웨이가 요청마다 새 ID를 만든다.
std::string new_request_id() {
    std::random_device device;
    std::string id = "chatcmpl-pa-";
    constexpr std::string_view hex = "0123456789abcdef";
    for (int i = 0; i < 24; ++i) id.push_back(hex[device() % 16]);
    return id;
}

std::expected<ProviderAnswer, AnswerError> parse_provider_answer(std::string_view body, ProviderProtocol protocol) {
    AnswerSax sax(protocol);
    bool ok = false;
    try {
        ok = json::sax_parse(body, &sax, json::input_format_t::json, /*strict=*/true);
    } catch (const std::exception&) {
        ok = false;
    }
    if (!ok || sax.failure) {
        return std::unexpected(sax.failure.value_or(AnswerError::Malformed));
    }
    const std::string_view expected_role = protocol == ProviderProtocol::GenerateContent
        ? std::string_view("model") : detail::role_name(core::MessageRole::Model);
    if (!sax.content || !sax.role || *sax.role != expected_role ||
        (protocol == ProviderProtocol::GenerateContent && (sax.candidate_count != 1 || sax.part_count != 1)) ||
        (protocol == ProviderProtocol::Messages && (sax.part_count != 1 || !sax.has_content_type))) {
        return std::unexpected(AnswerError::Malformed);
    }
    auto finish_reason = clean_finish_reason(protocol, sax.finish_reason);
    if (!finish_reason) return std::unexpected(AnswerError::Forbidden);
    if (protocol == ProviderProtocol::Messages && sax.has_usage && sax.usage.total_tokens == 0) {
        if (sax.usage.prompt_tokens > std::numeric_limits<std::int64_t>::max() - sax.usage.completion_tokens) {
            return std::unexpected(AnswerError::Malformed);
        }
        sax.usage.total_tokens = sax.usage.prompt_tokens + sax.usage.completion_tokens;
    }
    ProviderAnswer answer{std::move(*sax.content), std::move(*finish_reason), std::nullopt};
    if (sax.has_usage) {
        answer.usage = sax.usage;
    }
    return answer;
}

std::string client_response_body(std::string_view id, std::int64_t created, std::string_view model_alias,
                                 std::string_view content, std::string_view finish_reason,
                                 const std::optional<Usage>& usage) {
    json message = {{"role", detail::role_name(core::MessageRole::Model)}, {"content", content}};
    json body = {{"id", id},
                 {"object", "chat.completion"},
                 {"created", created},
                 {"model", model_alias},
                 {"choices", json::array({{{"index", 0}, {"message", std::move(message)}, {"finish_reason", finish_reason}}})}};
    if (usage) {
        body["usage"] = {{"prompt_tokens", usage->prompt_tokens},
                         {"completion_tokens", usage->completion_tokens},
                         {"total_tokens", usage->total_tokens}};
    }
    return body.dump();
}

}  // namespace prompt_airlock::gateway
