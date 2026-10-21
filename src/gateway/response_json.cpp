#include "prompt_airlock/gateway/response_json.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <limits>
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

// 위치를 따라가며 필요한 값만 꺼내는 SAX 핸들러. 위치는 "choices/0/message/content" 같은 경로로 본다.
class AnswerSax {
public:
    std::optional<AnswerError> failure;
    std::optional<core::SensitiveText> content;
    std::optional<std::string> role;
    std::string finish_reason;
    Usage usage;
    bool has_usage = false;

    bool null() {
        step();
        return true;  // null 은 금지 키에서도 "없음"으로 본다
    }
    bool boolean(bool) { return value(); }
    bool number_integer(json::number_integer_t v) { return integer(v); }
    bool number_unsigned(json::number_unsigned_t v) {
        return integer(v > static_cast<json::number_unsigned_t>(std::numeric_limits<std::int64_t>::max()) ? -1 : static_cast<std::int64_t>(v));
    }
    bool number_float(json::number_float_t, const std::string&) { return value(); }
    bool binary(json::binary_t&) { return fail(AnswerError::Malformed); }

    bool string(std::string& v) {
        if (!value()) {
            return false;
        }
        if (at({"choices", "0", "message", "content"})) {
            content = core::SensitiveText(std::move(v));
        } else if (at({"choices", "0", "message", "role"})) {
            role = v;
        } else if (at({"choices", "0", "finish_reason"})) {
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
        top.key = name;
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

    // choices 아래에서 금지 키가 값을 가지면 거절한다(null 은 위에서 통과).
    [[nodiscard]] bool forbidden_here() const {
        if (stack_.size() < 2 || stack_.front().key != "choices" || stack_.back().array) {
            return false;
        }
        return std::ranges::find(forbidden_keys, stack_.back().key) != forbidden_keys.end();
    }

    bool value() {
        step();
        return forbidden_here() ? fail(AnswerError::Forbidden) : true;
    }

    bool integer(std::int64_t v) {
        if (!value()) {
            return false;
        }
        if (at({"usage", "prompt_tokens"})) {
            usage.prompt_tokens = v;
            has_usage = true;
        } else if (at({"usage", "completion_tokens"})) {
            usage.completion_tokens = v;
            has_usage = true;
        } else if (at({"usage", "total_tokens"})) {
            usage.total_tokens = v;
            has_usage = true;
        }
        return true;
    }

    bool open(bool array) {
        if (!stack_.empty() && !value()) {
            return false;
        }
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
};

// finish_reason 은 짧은 소문자 이름만 넘긴다(provider 가 임의 문자열을 실어 보내지 못하게).
std::string clean_finish_reason(std::string_view reason) {
    const bool ok = !reason.empty() && reason.size() <= 32 &&
                    std::ranges::all_of(reason, [](char c) { return (c >= 'a' && c <= 'z') || c == '_'; });
    return ok ? std::string(reason) : std::string("stop");
}

}  // namespace

std::expected<ProviderAnswer, AnswerError> parse_provider_answer(std::string_view body) {
    AnswerSax sax;
    bool ok = false;
    try {
        ok = json::sax_parse(body, &sax, json::input_format_t::json, /*strict=*/true);
    } catch (const std::exception&) {
        ok = false;
    }
    if (!ok || sax.failure) {
        return std::unexpected(sax.failure.value_or(AnswerError::Malformed));
    }
    if (!sax.content || !sax.role || *sax.role != detail::role_name(core::MessageRole::Model)) {
        return std::unexpected(AnswerError::Malformed);
    }
    ProviderAnswer answer{std::move(*sax.content), clean_finish_reason(sax.finish_reason), std::nullopt};
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
