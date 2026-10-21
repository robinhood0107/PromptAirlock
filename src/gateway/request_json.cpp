#include "prompt_airlock/gateway/request_json.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "prompt_airlock/core/sensitive.hpp"
#include "role_name.hpp"

namespace prompt_airlock::gateway {
namespace {

using json = nlohmann::json;
using core::ReasonCode;

// 지금 읽고 있는 컨테이너가 요청의 어느 부분인가.
enum class Frame : std::uint8_t { Root, Messages, Message, Parts, Part, Stops, Format };

struct Level {
    Frame frame;
    std::string key;  // 객체에서 마지막으로 읽은 키
    std::set<std::string, std::less<>> seen;
};

constexpr std::string_view root_keys[] = {"model",       "messages", "max_tokens", "max_completion_tokens",
                                          "temperature", "top_p",    "stop",       "n",
                                          "stream",      "response_format"};

struct PendingMessage {
    std::optional<core::MessageRole> role;
    std::optional<core::ContentForm> form;
    std::vector<core::SensitiveText> parts;
};

struct PendingPart {
    bool is_text = false;
    bool typed = false;
    std::optional<core::SensitiveText> text;
};

// nlohmann SAX 핸들러. 이벤트마다 위치(Frame + 키)를 보고 허용 여부를 정한다. false 를 돌려주면 읽기가 멈춘다.
class RequestSax {
public:
    std::optional<ReasonCode> failure;
    core::PromptDocumentBuilder builder;
    core::RequestParamsInput params;

    bool null() { return scalar([](RequestSax& self, const std::string& key) { return self.root_null(key); }); }
    bool boolean(bool value) {
        return scalar([value](RequestSax& self, const std::string& key) {
            if (key == "stream") {
                self.params.stream = value;
                return true;
            }
            return self.fail(self.is_param(key) ? ReasonCode::ParameterOutOfRange : ReasonCode::FieldNotAllowed);
        });
    }
    bool number_integer(json::number_integer_t value) { return integer(value); }
    bool number_unsigned(json::number_unsigned_t value) {
        if (value > static_cast<json::number_unsigned_t>(std::numeric_limits<std::int64_t>::max())) {
            return fail(ReasonCode::ParameterOutOfRange);
        }
        return integer(static_cast<std::int64_t>(value));
    }
    bool number_float(json::number_float_t value, const std::string&) {
        return scalar([value](RequestSax& self, const std::string& key) {
            if (key == "temperature") {
                self.params.temperature = value;
                return true;
            }
            if (key == "top_p") {
                self.params.top_p = value;
                return true;
            }
            return self.fail(self.is_param(key) ? ReasonCode::ParameterOutOfRange : ReasonCode::FieldNotAllowed);
        });
    }
    bool binary(json::binary_t&) { return fail(ReasonCode::InvalidText); }

    // 값은 SensitiveText 로 옮긴다(파서 버퍼에 남은 원문을 지운다). 파서는 다음 값을 읽을 때 버퍼를 새로 채운다.
    bool string(std::string& value) {
        if (stack_.empty()) {
            return fail(ReasonCode::InvalidText);
        }
        Level& top = stack_.back();
        switch (top.frame) {
            case Frame::Root:
                if (top.key == "model") {
                    return true;  // 받기만 하고 provider 에는 고정 별칭을 보낸다
                }
                if (top.key == "stop") {
                    builder.add_stop(core::SensitiveText(std::move(value)));
                    return true;
                }
                return fail(is_param(top.key) ? ReasonCode::ParameterOutOfRange : ReasonCode::FieldNotAllowed);
            case Frame::Message:
                if (top.key == "role") {
                    message_.role = detail::parse_role(value);
                    return message_.role ? true : fail(ReasonCode::FieldNotAllowed);
                }
                // content 문자열
                message_.form = core::ContentForm::String;
                message_.parts.push_back(core::SensitiveText(std::move(value)));
                return true;
            case Frame::Part:
                if (top.key == "type") {
                    part_.typed = true;
                    part_.is_text = value == "text";
                    return part_.is_text ? true : fail(ReasonCode::ContentPartNotAllowed);
                }
                part_.text = core::SensitiveText(std::move(value));
                return true;
            case Frame::Stops:
                builder.add_stop(core::SensitiveText(std::move(value)));
                return true;
            case Frame::Format:
                if (value == "text") {
                    params.response_format = core::ResponseFormat::Text;
                } else if (value == "json_object") {
                    params.response_format = core::ResponseFormat::JsonObject;
                } else {
                    return fail(ReasonCode::ParameterOutOfRange);
                }
                return true;
            case Frame::Messages:
                return fail(ReasonCode::FieldNotAllowed);
            case Frame::Parts:
                return fail(ReasonCode::ContentPartNotAllowed);
        }
        return fail(ReasonCode::InvalidText);
    }

    bool start_object(std::size_t) {
        if (stack_.empty()) {
            return push(Frame::Root);
        }
        const Level& top = stack_.back();
        switch (top.frame) {
            case Frame::Messages:
                message_ = {};
                return push(Frame::Message);
            case Frame::Parts:
                part_ = {};
                return push(Frame::Part);
            case Frame::Root:
                if (top.key == "response_format") {
                    return push(Frame::Format);
                }
                return fail(is_param(top.key) ? ReasonCode::ParameterOutOfRange : ReasonCode::FieldNotAllowed);
            case Frame::Part:
                return fail(ReasonCode::ContentPartNotAllowed);
            case Frame::Message:
            case Frame::Stops:
            case Frame::Format:
                return fail(ReasonCode::FieldNotAllowed);
        }
        return fail(ReasonCode::InvalidText);
    }

    bool key(std::string& name) {
        Level& top = stack_.back();
        if (!top.seen.insert(name).second) {
            return fail(ReasonCode::FieldNotAllowed);  // 중복 키: 라이브러리는 마지막 값을 조용히 쓰므로 여기서 막는다
        }
        if (!allowed(top.frame, name)) {
            return fail(top.frame == Frame::Part ? ReasonCode::ContentPartNotAllowed
                        : top.frame == Frame::Format ? ReasonCode::ParameterOutOfRange
                                                     : ReasonCode::FieldNotAllowed);
        }
        top.key = name;
        return true;
    }

    bool end_object() {
        const Frame frame = stack_.back().frame;
        stack_.pop_back();
        if (frame == Frame::Part) {
            if (!part_.typed || !part_.is_text || !part_.text) {
                return fail(ReasonCode::ContentPartNotAllowed);
            }
            message_.parts.push_back(std::move(*part_.text));
        } else if (frame == Frame::Message) {
            if (!message_.role || !message_.form) {
                return fail(ReasonCode::FieldNotAllowed);
            }
            builder.add_message(*message_.role, *message_.form, std::move(message_.parts));
        } else if (frame == Frame::Format && !params.response_format) {
            return fail(ReasonCode::ParameterOutOfRange);
        }
        return true;
    }

    bool start_array(std::size_t) {
        if (stack_.empty()) {
            return fail(ReasonCode::InvalidText);
        }
        const Level& top = stack_.back();
        if (top.frame == Frame::Root && top.key == "messages") {
            return push(Frame::Messages);
        }
        if (top.frame == Frame::Root && top.key == "stop") {
            return push(Frame::Stops);
        }
        if (top.frame == Frame::Message && top.key == "content") {
            message_.form = core::ContentForm::TextParts;
            return push(Frame::Parts);
        }
        if (top.frame == Frame::Part || top.frame == Frame::Parts) {
            return fail(ReasonCode::ContentPartNotAllowed);
        }
        return fail(top.frame == Frame::Root && is_param(top.key) ? ReasonCode::ParameterOutOfRange
                                                                   : ReasonCode::FieldNotAllowed);
    }

    bool end_array() {
        stack_.pop_back();
        return true;
    }

    bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) {
        return fail(ReasonCode::InvalidText);
    }

private:
    bool fail(ReasonCode code) {
        if (!failure) {
            failure = code;
        }
        return false;
    }

    bool push(Frame frame) {
        if (stack_.size() >= max_json_depth) {
            return fail(ReasonCode::InvalidText);
        }
        stack_.push_back({frame, {}, {}});
        return true;
    }

    static bool is_param(std::string_view key) { return key != "model" && key != "messages"; }

    static bool allowed(Frame frame, std::string_view key) {
        switch (frame) {
            case Frame::Root: return std::ranges::find(root_keys, key) != std::end(root_keys);
            case Frame::Message: return key == "role" || key == "content";
            case Frame::Part: return key == "type" || key == "text";
            case Frame::Format: return key == "type";
            case Frame::Messages:
            case Frame::Parts:
            case Frame::Stops: return false;
        }
        return false;
    }

    // 값 하나(문자열 제외). 객체 키 자리에서만 오며, 배열 원소로 오면 모양이 틀린 것이다.
    template <class F>
    bool scalar(F&& on_root_value) {
        if (stack_.empty()) {
            return fail(ReasonCode::InvalidText);
        }
        const Level& top = stack_.back();
        if (top.frame == Frame::Root) {
            return on_root_value(*this, top.key);
        }
        if (top.frame == Frame::Part || top.frame == Frame::Parts) {
            return fail(ReasonCode::ContentPartNotAllowed);
        }
        return fail(top.frame == Frame::Format ? ReasonCode::ParameterOutOfRange : ReasonCode::FieldNotAllowed);
    }

    // 선택 파라미터의 null 은 없는 것과 같다. 필수 필드나 다른 자리의 null 은 거절한다.
    bool root_null(const std::string& key) {
        if (key == "model" || key == "messages") {
            return fail(ReasonCode::FieldNotAllowed);
        }
        return true;
    }

    bool integer(std::int64_t value) {
        return scalar([value](RequestSax& self, const std::string& key) {
            if (key == "max_tokens") {
                self.params.max_tokens = value;
            } else if (key == "max_completion_tokens") {
                self.params.max_completion_tokens = value;
            } else if (key == "n") {
                self.params.n = value;
            } else if (key == "temperature") {
                self.params.temperature = static_cast<double>(value);
            } else if (key == "top_p") {
                self.params.top_p = static_cast<double>(value);
            } else {
                return self.fail(self.is_param(key) ? ReasonCode::ParameterOutOfRange : ReasonCode::FieldNotAllowed);
            }
            return true;
        });
    }

    std::vector<Level> stack_;
    PendingMessage message_;
    PendingPart part_;
};

}  // namespace

std::expected<ParsedRequest, core::Rejection> parse_request(std::string_view body) {
    RequestSax sax;
    bool ok = false;
    try {
        ok = json::sax_parse(body, &sax, json::input_format_t::json, /*strict=*/true);
    } catch (const std::exception&) {
        // 라이브러리 예외(메모리 부족 등)는 입구에서 거절로 바꾼다
        ok = false;
    }
    if (!ok || sax.failure) {
        return std::unexpected(core::Rejection::of(sax.failure.value_or(ReasonCode::InvalidText)));
    }
    auto document = std::move(sax.builder).build();
    if (!document) {
        return std::unexpected(core::Rejection::from_error(document.error()));
    }
    return ParsedRequest{std::move(*document), sax.params};
}

}  // namespace prompt_airlock::gateway
