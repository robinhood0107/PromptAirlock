#include "prompt_airlock/gateway/provider_json.hpp"

#include <nlohmann/json.hpp>

#include "role_name.hpp"

namespace prompt_airlock::gateway {

std::string provider_request_body(const core::ProviderRequest& request, std::string_view model_alias) {
    using json = nlohmann::json;
    json messages = json::array();
    for (const auto& message : request.messages()) {
        json content;
        if (message.form == core::ContentForm::String && message.parts.size() == 1) {
            content = message.parts.front().view();
        } else {
            content = json::array();
            for (const auto& part : message.parts) {
                content.push_back({{"type", "text"}, {"text", part.view()}});
            }
        }
        messages.push_back({{"role", detail::role_name(message.role)}, {"content", std::move(content)}});
    }
    const auto& params = request.params();
    json body = {{"model", model_alias},
                 {"messages", std::move(messages)},
                 {"max_tokens", params.max_output_tokens()},
                 {"n", 1},
                 {"stream", false}};
    if (params.temperature()) {
        body["temperature"] = *params.temperature();
    }
    if (params.top_p()) {
        body["top_p"] = *params.top_p();
    }
    if (!request.stop().empty()) {
        json stop = json::array();
        for (const auto& s : request.stop()) {
            stop.push_back(s.view());
        }
        body["stop"] = std::move(stop);
    }
    if (params.response_format()) {
        body["response_format"] = {
            {"type", *params.response_format() == core::ResponseFormat::JsonObject ? "json_object" : "text"}};
    }
    return body.dump();
}

}  // namespace prompt_airlock::gateway
