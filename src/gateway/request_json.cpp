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
enum class Frame : std::uint8_t { Root, Messages, Message, Parts, Part, File, Stops, Format };

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
    bool is_file = false;
    std::optional<std::string> extension;
    std::optional<core::SensitiveText> bytes;
    bool typed = false;
    std::optional<core::SensitiveText> text;
};

// 파일명은 확장자를 정하는 데만 쓴다. 로컬·원격 경로나 제어 문자를 이름으로 받지 않는다.
std::optional<std::string> file_extension(std::string_view name) {
    if (name.empty() || name.size() > 1024 ||
        std::ranges::any_of(name, [](unsigned char c) { return c < 32 || c == 127 || c == '/' || c == '\\' || c == ':'; })) {
        return std::nullopt;
    }
    const auto dot = name.rfind('.');
    if (dot == std::string_view::npos || dot + 1 == name.size()) return std::string();
    if (name.size() - dot > 17) return std::string();
    std::string ext(name.substr(dot + 1));
    for (auto& c : ext) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return std::string();
    }
    return ext;
}

// 인라인 data URI만 받으며, padding 위치와 남는 비트까지 검사한다.
std::expected<core::SensitiveText, ReasonCode> decode_file(std::string_view data, std::size_t remaining) {
    const auto comma = data.find(',');
    if (!data.starts_with("data:") || comma == std::string_view::npos || comma > 128 ||
        !data.substr(0, comma).ends_with(";base64")) return std::unexpected(ReasonCode::ContentPartNotAllowed);
    const auto mime = data.substr(5, comma - 5 - 7);
    if (mime.empty() || std::ranges::any_of(mime, [](unsigned char c) {
            return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                     c == '/' || c == '-' || c == '+' || c == '.');
        })) return std::unexpected(ReasonCode::ContentPartNotAllowed);
    data.remove_prefix(comma + 1);
    if (data.empty() || data.size() % 4 != 0) return std::unexpected(ReasonCode::ContentPartNotAllowed);
    const auto padding = static_cast<std::size_t>(data.back() == '=') + (data[data.size() - 2] == '=' ? 1U : 0U);
    const auto bytes = data.size() / 4 * 3 - padding;
    if (bytes > remaining) return std::unexpected(ReasonCode::PromptTooLarge);
    std::string out;
    out.reserve(bytes);
    const auto digit = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        return c == '+' ? 62 : c == '/' ? 63 : -1;
    };
    for (std::size_t i = 0; i < data.size(); i += 4) {
        const int a = digit(data[i]), b = digit(data[i + 1]);
        const int c = data[i + 2] == '=' ? 0 : digit(data[i + 2]);
        const int d = data[i + 3] == '=' ? 0 : digit(data[i + 3]);
        const bool last = i + 4 == data.size();
        if (a < 0 || b < 0 || c < 0 || d < 0 || (!last && (data[i + 2] == '=' || data[i + 3] == '=')) ||
            (data[i + 2] == '=' && (data[i + 3] != '=' || (b & 15) != 0)) ||
            (data[i + 3] == '=' && data[i + 2] != '=' && (c & 3) != 0)) {
            core::SensitiveText discard(std::move(out));
            return std::unexpected(ReasonCode::ContentPartNotAllowed);
        }
        out.push_back(static_cast<char>((a << 2) | (b >> 4)));
        if (data[i + 2] != '=') out.push_back(static_cast<char>((b << 4) | (c >> 2)));
        if (data[i + 3] != '=') out.push_back(static_cast<char>((c << 6) | d));
    }
    return core::SensitiveText(std::move(out));
}

// nlohmann SAX 핸들러. 이벤트마다 위치(Frame + 키)를 보고 허용 여부를 정한다. false 를 돌려주면 읽기가 멈춘다.
class RequestSax {
public:
    std::optional<ReasonCode> failure;
    core::PromptDocumentBuilder builder;
    core::RequestParamsInput params;
    std::vector<FilePart> files;

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
                    if (!count_text(value.size())) return false;
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
                if (!count_text(value.size())) return false;
                message_.parts.push_back(core::SensitiveText(std::move(value)));
                return true;
            case Frame::Part:
                if (top.key == "type") {
                    part_.typed = true;
                    part_.is_text = value == "text";
                    part_.is_file = value == "file";
                    return part_.is_text || part_.is_file ? true : fail(ReasonCode::ContentPartNotAllowed);
                }
                if (top.key != "text") return fail(ReasonCode::ContentPartNotAllowed);
                if (!count_text(value.size())) return false;
                part_.text = core::SensitiveText(std::move(value));
                return true;
            case Frame::File: {
                if (top.key == "filename") {
                    part_.extension = file_extension(value);
                    core::SensitiveText discarded(std::move(value));
                    return part_.extension ? true : fail(ReasonCode::ContentPartNotAllowed);
                }
                core::SensitiveText encoded(std::move(value));
                if (auto decoded = decode_file(encoded.view(), max_file_bytes - file_bytes_); decoded) {
                    file_bytes_ += decoded->size();
                    part_.bytes.emplace(std::move(*decoded));
                    return true;
                } else {
                    return fail(decoded.error());
                }
            }
            case Frame::Stops:
                if (!count_text(value.size())) return false;
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
                if (top.key == "file") return push(Frame::File);
                return fail(ReasonCode::ContentPartNotAllowed);
            case Frame::File:
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
            if (!part_.typed) return fail(ReasonCode::ContentPartNotAllowed);
            if (part_.is_file && !part_.text && part_.bytes && part_.extension) {
                if (files.size() == max_file_parts) return fail(ReasonCode::PromptTooLarge);
                files.push_back({message_count_, static_cast<std::uint32_t>(message_.parts.size()),
                                 std::move(*part_.extension), std::move(*part_.bytes)});
                message_.parts.emplace_back(std::string());
            } else if (part_.is_text && part_.text && !part_.bytes && !part_.extension) {
                message_.parts.push_back(std::move(*part_.text));
            } else {
                return fail(ReasonCode::ContentPartNotAllowed);
            }
        } else if (frame == Frame::File) {
            if (!part_.extension || !part_.bytes) return fail(ReasonCode::ContentPartNotAllowed);
        } else if (frame == Frame::Message) {
            if (!message_.role || !message_.form) {
                return fail(ReasonCode::FieldNotAllowed);
            }
            builder.add_message(*message_.role, *message_.form, std::move(message_.parts));
            ++message_count_;
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
        if (top.frame == Frame::Part || top.frame == Frame::File || top.frame == Frame::Parts) {
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
            case Frame::Part: return key == "type" || key == "text" || key == "file";
            case Frame::File: return key == "filename" || key == "file_data";
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
        if (top.frame == Frame::Part || top.frame == Frame::File || top.frame == Frame::Parts) {
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

    bool count_text(std::size_t bytes) {
        if (bytes > core::max_prompt_bytes - text_bytes_) return fail(ReasonCode::PromptTooLarge);
        text_bytes_ += bytes;
        return true;
    }
    std::size_t text_bytes_ = 0;
    std::size_t file_bytes_ = 0;
    std::uint32_t message_count_ = 0;
    std::vector<Level> stack_;
    PendingMessage message_;
    PendingPart part_;
};

}  // namespace

std::expected<ParsedRequest, core::Rejection> parse_request(std::string_view body) {
    if (body.size() > max_file_json_bytes) return std::unexpected(core::Rejection::of(ReasonCode::PromptTooLarge));
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
    auto document = std::move(sax.builder).build(sax.files.empty() ? core::DocumentKind::Text
                                                                 : core::DocumentKind::ExtractedFiles);
    if (!document) {
        return std::unexpected(core::Rejection::from_error(document.error()));
    }
    return ParsedRequest{std::move(*document), sax.params, std::move(sax.files)};
}

}  // namespace prompt_airlock::gateway
