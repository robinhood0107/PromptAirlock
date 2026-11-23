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

std::expected<std::string, ProviderRequestError> provider_request_body(const core::ProviderRequest& request,
                                                                      std::string_view model_alias,
                                                                      ProviderProtocol protocol) {
    using json = nlohmann::json;
    if (protocol == ProviderProtocol::ChatCompletions) {
        return provider_request_body(request, model_alias);
    }

    const auto& params = request.params();
    if (protocol == ProviderProtocol::LocalCliText) {
        if (params.temperature() || params.top_p() || !request.stop().empty() ||
            (params.response_format() && *params.response_format() == core::ResponseFormat::JsonObject) ||
            request.messages().size() != 1) {
            return std::unexpected(ProviderRequestError::Unsupported);
        }
        const auto& message = request.messages().front();
        if (message.role != core::MessageRole::User || message.parts.size() != 1 || message.parts.front().empty()) {
            return std::unexpected(ProviderRequestError::Unsupported);
        }
        return std::string(message.parts.front().view());
    }

    json messages = json::array();
    json system = json::array();
    bool dialogue_started = false;
    bool has_user_message = false;
    for (const auto& message : request.messages()) {
        if (message.role == core::MessageRole::System) {
            if (dialogue_started) return std::unexpected(ProviderRequestError::Unsupported);
            for (const auto& part : message.parts) {
                if (protocol == ProviderProtocol::GenerateContent) {
                    system.push_back({{"text", part.view()}});
                } else {
                    system.push_back({{"type", "text"}, {"text", part.view()}});
                }
            }
            continue;
        }
        if (message.role == core::MessageRole::Developer || message.parts.empty()) {
            return std::unexpected(ProviderRequestError::Unsupported);
        }
        dialogue_started = true;
        if (message.role == core::MessageRole::User) has_user_message = true;
        if (protocol == ProviderProtocol::GenerateContent) {
            json parts = json::array();
            for (const auto& part : message.parts) parts.push_back({{"text", part.view()}});
            const std::string_view role = message.role == core::MessageRole::User ? "user" : "model";
            messages.push_back({{"role", role}, {"parts", std::move(parts)}});
        } else {
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
    }
    if (messages.empty() || !has_user_message) return std::unexpected(ProviderRequestError::Unsupported);

    json body;
    if (protocol == ProviderProtocol::GenerateContent) {
        body = {{"contents", std::move(messages)},
                {"generationConfig", {{"candidateCount", 1}, {"maxOutputTokens", params.max_output_tokens()}}}};
        if (!system.empty()) body["systemInstruction"] = {{"parts", std::move(system)}};
        auto& generation = body["generationConfig"];
        if (params.temperature()) generation["temperature"] = *params.temperature();
        if (params.top_p()) generation["topP"] = *params.top_p();
        if (params.response_format()) {
            generation["responseMimeType"] = *params.response_format() == core::ResponseFormat::JsonObject
                ? "application/json" : "text/plain";
        }
        if (!request.stop().empty()) {
            json stop = json::array();
            for (const auto& sequence : request.stop()) stop.push_back(sequence.view());
            generation["stopSequences"] = std::move(stop);
        }
        return body.dump();
    }

    if (params.temperature() || params.top_p() ||
        (params.response_format() && *params.response_format() == core::ResponseFormat::JsonObject)) {
        return std::unexpected(ProviderRequestError::Unsupported);
    }
    body = {{"model", model_alias}, {"max_tokens", params.max_output_tokens()}, {"messages", std::move(messages)}};
    if (!system.empty()) body["system"] = std::move(system);
    if (!request.stop().empty()) {
        json stop = json::array();
        for (const auto& sequence : request.stop()) stop.push_back(sequence.view());
        body["stop_sequences"] = std::move(stop);
    }
    return body.dump();
}

}  // namespace prompt_airlock::gateway
