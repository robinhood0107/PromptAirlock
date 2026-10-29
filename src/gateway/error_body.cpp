#include "prompt_airlock/gateway/error_body.hpp"

#include <nlohmann/json.hpp>

#include <string_view>

namespace prompt_airlock::gateway {
namespace {

using json = nlohmann::json;
using core::ReasonCode;

struct Shape {
    unsigned status;
    std::string_view type;
    std::string_view code;
    std::string_view message;
};

std::string render(const Shape& shape, const json& blocked_types) {
    json error = {{"message", shape.message}, {"type", shape.type}, {"param", nullptr}, {"code", shape.code}};
    if (!blocked_types.empty()) {
        error["blocked_types"] = blocked_types;
    }
    return json{{"error", std::move(error)}}.dump();
}

Shape entry_shape(EntryError error) {
    switch (error) {
        case EntryError::Unauthorized:
            return {401, "authentication_error", "unauthorized", "Origin authentication failed."};
        case EntryError::TooManyFailures:
            return {429, "rate_limit_error", "too_many_auth_failures", "Too many failed attempts. Try again later."};
        case EntryError::NotFound:
            return {404, "invalid_request_error", "not_found", "Unknown endpoint."};
        case EntryError::MethodNotAllowed:
            return {405, "invalid_request_error", "method_not_allowed", "Only POST is accepted."};
        case EntryError::BodyTooLarge:
            return {413, "invalid_request_error", "body_too_large", "Request body is too large."};
        case EntryError::UnsupportedMediaType:
            return {415, "invalid_request_error", "unsupported_media_type", "Content-Type must be application/json."};
        case EntryError::BadRequest:
            return {400, "invalid_request_error", "bad_request", "Malformed HTTP request."};
        case EntryError::Unavailable:
            return {503, "api_error", "unavailable", "The gateway cannot process requests right now."};
        case EntryError::Overloaded:
            return {503, "api_error", "overloaded", "The gateway is busy. Try again later."};
        case EntryError::ProviderFailed:
            return {502, "api_error", "provider_error", "The upstream model did not return a usable response."};
    }
    return {500, "api_error", "internal_error", "Internal error."};
}

// 사유 코드 범위(ReasonCode 주석)마다 상태 코드와 문장을 고정한다. 코드 이름은 core 가 정한다.
Shape rejection_shape(ReasonCode code) {
    const std::string_view name = core::reason_code_name(code);
    const auto value = static_cast<unsigned>(code);
    if (code == ReasonCode::PromptTooLarge) {
        return {413, "invalid_request_error", name, "The prompt is too large."};
    }
    if (value < 200) {
        return {403, "permission_error", name, "This request's data grade cannot be sent to an external model."};
    }
    if (value < 400) {
        return {400, "invalid_request_error", name, "The request is not allowed by the gateway."};
    }
    if (value < 500) {
        return {400, "invalid_request_error", name, "The prompt contains information that cannot be sent."};
    }
    if (value < 900) {
        return {502, "api_error", name, "The model response was rejected by the gateway."};
    }
    if (code == ReasonCode::InternalError) {
        return {500, "api_error", name, "Internal error."};
    }
    return {503, "api_error", name, "A required safety check is unavailable."};
}

}  // namespace

JsonResponse error_response(EntryError error) {
    const Shape shape = entry_shape(error);
    return {shape.status, render(shape, json::array())};
}

JsonResponse error_response(const core::UserRejection& rejection) {
    const Shape shape = rejection_shape(rejection.code);
    json types = json::array();
    rejection.blocked_types.for_each([&](core::EntityType type) { types.push_back(core::entity_type_name(type)); });
    return {shape.status, render(shape, types)};
}

}  // namespace prompt_airlock::gateway
