#pragma once

#include <expected>
#include <filesystem>
#include <optional>
#include <stop_token>
#include <string>
#include <variant>
#include <vector>

#include "prompt_airlock/extract/runner.hpp"
#include "prompt_airlock/gateway/request_json.hpp"

namespace prompt_airlock::gateway {

struct FileStatistics {
    std::size_t bytes = 0;
    std::string sha256;
    std::optional<extract::DocumentFormat> format;
    std::optional<std::uint32_t> pages;
    std::size_t characters = 0;
    extract::Omitted omitted;
};

// 원문 위치는 내부에서만 쓴다. 사용자 응답과 감사에는 이 표를 넣지 않는다.
struct FileLocation {
    std::size_t file;
    std::uint32_t document;
    std::size_t block;
    core::SegmentIndex segment;
    core::ByteSpan span;
    core::SensitiveText where;
};

struct ResolvedDocuments {
    core::PromptDocument document;
    std::vector<FileLocation> locations;
};

using DocumentFailure = std::variant<extract::ExtractError, extract::RunError, core::InputError>;

[[nodiscard]] std::expected<ResolvedDocuments, DocumentFailure> resolve_documents(
    ParsedRequest& request, const std::filesystem::path& executable, std::vector<FileStatistics>& statistics,
    std::stop_token stop);

}  // namespace prompt_airlock::gateway
