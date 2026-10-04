// Vault 클라이언트. 요청-응답 순차 처리, 응답 request_id·버전 확인, 실패 시 broken(fail closed).
#include "prompt_airlock/vault/client.hpp"

#include <array>
#include <string>

#include "vault_v1.pb.h"

namespace prompt_airlock::vault {
namespace pb = ::prompt_airlock::vault::v1;

namespace {

ErrorCode from_proto(pb::ErrorCode c) {
    switch (c) {
        case pb::UNSUPPORTED_VERSION: return ErrorCode::UnsupportedVersion;
        case pb::MALFORMED_REQUEST: return ErrorCode::MalformedRequest;
        case pb::FRAME_TOO_LARGE: return ErrorCode::FrameTooLarge;
        case pb::AUTH_REQUIRED: return ErrorCode::AuthRequired;
        case pb::AUTH_FAILED: return ErrorCode::AuthFailed;
        case pb::OVERLOADED: return ErrorCode::Overloaded;
        case pb::SCOPE_NOT_FOUND: return ErrorCode::ScopeNotFound;
        case pb::SCOPE_EXPIRED: return ErrorCode::ScopeExpired;
        case pb::TOKEN_NOT_FOUND: return ErrorCode::TokenNotFound;
        case pb::MALFORMED_TOKEN: return ErrorCode::MalformedToken;
        case pb::SCOPE_LIMIT: return ErrorCode::ScopeLimit;
        case pb::MAPPING_LIMIT: return ErrorCode::MappingLimit;
        case pb::VALUE_TOO_LARGE: return ErrorCode::ValueTooLarge;
        case pb::INVALID_ARGUMENT: return ErrorCode::InvalidArgument;
        case pb::INTERNAL: return ErrorCode::Internal;
        case pb::SHUTTING_DOWN: return ErrorCode::ShuttingDown;
        default: return ErrorCode::ProtocolViolation;
    }
}

// 서버가 응답 뒤 연결을 닫는 오류. 클라이언트도 더 쓰지 않는다.
bool closes_connection(ErrorCode c) {
    switch (c) {
        case ErrorCode::UnsupportedVersion:
        case ErrorCode::MalformedRequest:
        case ErrorCode::FrameTooLarge:
        case ErrorCode::AuthRequired:
        case ErrorCode::AuthFailed:
        case ErrorCode::ProtocolViolation:
            return true;
        default:
            return false;
    }
}

std::string scope_bytes(const ScopeId& s) {
    const auto b = s.bytes();
    return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

}  // namespace

struct VaultClient::Impl {
    std::unique_ptr<ByteStream> stream;
    ClientOptions opts;
    std::uint64_t next_id = 1;
    bool broken = false;

    Result<pb::Response> fail_broken(ErrorCode c) {
        broken = true;
        if (stream) {
            stream->close();
        }
        return fail(c);
    }

    // 요청을 보내고 응답 하나를 받는다. 요청 안의 원문 필드는 호출자가 지운다.
    Result<pb::Response> call(pb::Request& req) {
        if (broken) {
            return fail(ErrorCode::ClientBroken);
        }
        const std::uint64_t id = next_id++;
        req.set_protocol_version(pb::PROTOCOL_VERSION_V1);
        req.set_request_id(id);
        const std::size_t n = req.ByteSizeLong();
        if (n > opts.max_frame_bytes) {
            return fail(ErrorCode::ValueTooLarge);
        }
        std::string frame(4 + n, '\0');
        frame[0] = static_cast<char>((n >> 24) & 0xff);
        frame[1] = static_cast<char>((n >> 16) & 0xff);
        frame[2] = static_cast<char>((n >> 8) & 0xff);
        frame[3] = static_cast<char>(n & 0xff);
        if (!req.SerializeToArray(frame.data() + 4, static_cast<int>(n))) {
            secure_wipe(frame);
            return fail_broken(ErrorCode::Io);
        }
        auto w = stream->write_all({reinterpret_cast<const std::uint8_t*>(frame.data()), frame.size()}, opts.io_timeout);
        secure_wipe(frame);
        if (!w) {
            return fail_broken(w.error().code);
        }
        std::array<std::uint8_t, 4> hdr{};
        if (auto r = stream->read_exact(hdr, opts.io_timeout); !r) {
            return fail_broken(r.error().code);
        }
        const std::size_t len = (std::size_t{hdr[0]} << 24) | (std::size_t{hdr[1]} << 16) | (std::size_t{hdr[2]} << 8) | hdr[3];
        if (len > opts.max_frame_bytes) {
            return fail_broken(ErrorCode::ProtocolViolation);
        }
        std::string body(len, '\0');
        if (auto r = stream->read_exact({reinterpret_cast<std::uint8_t*>(body.data()), body.size()}, opts.io_timeout); !r) {
            secure_wipe(body);
            return fail_broken(r.error().code);
        }
        pb::Response resp;
        const bool parsed = resp.ParseFromString(body);
        secure_wipe(body);
        if (!parsed || resp.protocol_version() != pb::PROTOCOL_VERSION_V1) {
            return fail_broken(ErrorCode::ProtocolViolation);
        }
        if (resp.has_error()) {
            const ErrorCode code = from_proto(resp.error().code());
            // request_id 0 은 연결 수준 오류(frame 크기, 연결 수 한도 등)다.
            if (resp.request_id() == 0 || closes_connection(code)) {
                return fail_broken(code);
            }
            if (resp.request_id() != id) {
                return fail_broken(ErrorCode::ProtocolViolation);
            }
            return fail(code);
        }
        if (resp.request_id() != id) {
            return fail_broken(ErrorCode::ProtocolViolation);
        }
        return resp;
    }
};

VaultClient::VaultClient(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
VaultClient::VaultClient(VaultClient&&) noexcept = default;
VaultClient& VaultClient::operator=(VaultClient&&) noexcept = default;
VaultClient::~VaultClient() = default;

bool VaultClient::broken() const noexcept { return !impl_ || impl_->broken; }

Result<VaultClient> VaultClient::connect(const Endpoint& ep, const AuthSecret& secret, const ClientOptions& opts) {
    auto stream = open_stream(ep, opts.stream);
    if (!stream) {
        return std::unexpected(stream.error());
    }
    auto impl = std::make_unique<Impl>();
    impl->stream = std::move(*stream);
    impl->opts = opts;
    pb::Request req;
    const auto s = secret.bytes();
    req.mutable_hello()->set_auth_secret(reinterpret_cast<const char*>(s.data()), s.size());
    auto resp = impl->call(req);
    secure_wipe(*req.mutable_hello()->mutable_auth_secret());
    if (!resp) {
        return std::unexpected(resp.error());
    }
    if (!resp->has_hello()) {
        return fail(ErrorCode::ProtocolViolation);
    }
    return VaultClient(std::move(impl));
}

Result<ScopeId> VaultClient::create_scope(std::chrono::milliseconds ttl) {
    if (!impl_) {
        return fail(ErrorCode::ClientBroken);
    }
    if (ttl.count() <= 0) {
        return fail(ErrorCode::InvalidArgument);
    }
    pb::Request req;
    req.mutable_create_scope()->set_ttl_ms(static_cast<std::uint64_t>(ttl.count()));
    auto resp = impl_->call(req);
    if (!resp) {
        return std::unexpected(resp.error());
    }
    if (!resp->has_create_scope()) {
        (void)impl_->fail_broken(ErrorCode::ProtocolViolation);
        return fail(ErrorCode::ProtocolViolation);
    }
    const auto& id = resp->create_scope().scope_id();
    return ScopeId::from_bytes({reinterpret_cast<const std::uint8_t*>(id.data()), id.size()});
}

Result<Token> VaultClient::create_token(const ScopeId& scope, const EntityLabel& label, std::string_view value) {
    if (!impl_) {
        return fail(ErrorCode::ClientBroken);
    }
    pb::Request req;
    auto* ct = req.mutable_create_token();
    ct->set_scope_id(scope_bytes(scope));
    ct->set_entity_type(label.str());
    ct->set_value(value.data(), value.size());
    auto resp = impl_->call(req);
    secure_wipe(*ct->mutable_value());
    if (!resp) {
        return std::unexpected(resp.error());
    }
    if (!resp->has_create_token()) {
        (void)impl_->fail_broken(ErrorCode::ProtocolViolation);
        return fail(ErrorCode::ProtocolViolation);
    }
    return Token(resp->create_token().token());
}

Result<SensitiveValue> VaultClient::resolve_exact(const ScopeId& scope, const Token& token) {
    if (!impl_) {
        return fail(ErrorCode::ClientBroken);
    }
    pb::Request req;
    auto* re = req.mutable_resolve_exact();
    re->set_scope_id(scope_bytes(scope));
    re->set_token(token.str());
    auto resp = impl_->call(req);
    if (!resp) {
        return std::unexpected(resp.error());
    }
    if (!resp->has_resolve_exact()) {
        (void)impl_->fail_broken(ErrorCode::ProtocolViolation);
        return fail(ErrorCode::ProtocolViolation);
    }
    auto* r = resp->mutable_resolve_exact();
    SensitiveValue v(r->entity_type(), std::move(*r->mutable_value()));
    secure_wipe(*r->mutable_value());
    return v;
}

Result<void> VaultClient::drop_scope(const ScopeId& scope) {
    if (!impl_) {
        return fail(ErrorCode::ClientBroken);
    }
    pb::Request req;
    req.mutable_drop_scope()->set_scope_id(scope_bytes(scope));
    auto resp = impl_->call(req);
    if (!resp) {
        return std::unexpected(resp.error());
    }
    if (!resp->has_drop_scope()) {
        (void)impl_->fail_broken(ErrorCode::ProtocolViolation);
        return fail(ErrorCode::ProtocolViolation);
    }
    return {};
}

}  // namespace prompt_airlock::vault
