#include "prompt_airlock/gateway/documents.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <span>
#include <utility>

#include "prompt_airlock/core/sha256.hpp"
#include "prompt_airlock/core/utf8.hpp"

namespace prompt_airlock::gateway {
namespace {

struct Location {
    std::size_t file;
    std::uint32_t document;
    std::size_t block;
    core::ByteSpan span;
    core::SensitiveText where;
};

struct Part {
    core::SensitiveText text;
    std::vector<Location> locations;
};

struct Wipe {
        extract::ExtractedDocument& document;
        std::string& text;
        ~Wipe() {
            core::SensitiveText discarded(std::move(text));
            for (auto& b : document.blocks) {
                core::SensitiveText content(std::move(b.text));
                core::SensitiveText where(std::move(b.where));
            }
        }
};

std::expected<std::vector<Part>, DocumentFailure> assemble(extract::ExtractedDocument extracted,
                                                          std::size_t file, std::size_t& remaining) {
    std::vector<Part> parts;
    std::optional<std::uint32_t> document;
    std::uint32_t region = 0;
    std::string text;
    std::vector<Location> locations;
    Wipe wipe{extracted, text};
    const auto flush = [&] {
        if (!text.empty()) parts.push_back({core::SensitiveText(std::move(text)), std::move(locations)});
        text.clear();
        locations.clear();
    };
    for (std::size_t index = 0; index < extracted.blocks.size(); ++index) {
        auto& block = extracted.blocks[index];
        if (const auto valid = core::validate_utf8(block.text); !valid) {
            return std::unexpected(valid.error());
        }
        if (block.text.empty()) return std::unexpected(extract::RunError::BadOutput);
        if (document && *document != block.document) flush();
        const std::string_view separator = text.empty() ? "" : region != block.region ? "\n|\n" : "\n";
        if (separator.size() > remaining || block.text.size() > remaining - separator.size()) {
            core::SensitiveText discarded(std::move(text));
            return std::unexpected(extract::ExtractError::TooLarge);
        }
        remaining -= separator.size() + block.text.size();
        text.append(separator);
        const auto begin = text.size();
        text.append(block.text);
        core::SensitiveText discarded(std::move(block.text));
        locations.push_back({file, block.document, index,
                             *core::ByteSpan::make(core::Utf8ByteOffset{begin}, core::Utf8ByteOffset{text.size()}),
                             core::SensitiveText(std::move(block.where))});
        document = block.document;
        region = block.region;
    }
    flush();
    if (parts.empty()) return std::unexpected(extract::ExtractError::NoText);
    return parts;
}

}  // namespace

std::expected<ResolvedDocuments, DocumentFailure> resolve_documents(
    ParsedRequest& request, const std::filesystem::path& executable, std::vector<FileStatistics>& statistics,
    std::stop_token stop) {
    if (request.files.empty()) return ResolvedDocuments{std::move(request.document), {}};
    using Key = std::pair<std::uint32_t, std::uint32_t>;
    std::map<Key, std::vector<Part>> projected;
    std::size_t remaining = core::max_document_text_bytes;
    for (std::size_t index = 0; index < request.files.size(); ++index) {
        if (stop.stop_requested()) return std::unexpected(extract::RunError::Cancelled);
        auto& file = request.files[index];
        statistics.push_back({file.bytes.size(), core::sha256_hex(std::as_bytes(std::span(file.bytes.view()))),
                              std::nullopt, std::nullopt, 0, {}});
        auto& stat = statistics.back();
        // LaTeX·Typst 는 추출기 옆의 pandoc 으로 매크로·함수를 펼친 글을 검사한다. pandoc 이 없거나 실패하면 거절.
        std::string_view hint = file.extension;
        core::SensitiveText converted;
        if (const auto reader = extract::markup_reader(file.extension)) {
            const auto pandoc = executable.parent_path() / ("pandoc" + executable.extension().string());
            if (!std::filesystem::is_regular_file(pandoc)) return std::unexpected(extract::ExtractError::Unsupported);
            auto plain = extract::convert_markup(pandoc, *reader, std::as_bytes(std::span(file.bytes.view())), {}, stop);
            if (!plain) return std::unexpected(plain.error());
            converted = core::SensitiveText(std::move(*plain));
            file.bytes = core::SensitiveText(std::string());
            hint = "txt";
        }
        const auto input = hint == "txt" && extract::markup_reader(file.extension) ? converted.view() : file.bytes.view();
        auto extracted = extract::extract_in_child(executable, hint, std::as_bytes(std::span(input)), {}, stop);
        converted = core::SensitiveText(std::string());
        file.bytes = core::SensitiveText(std::string());
        if (!extracted) return std::unexpected(extracted.error());
        if (!*extracted) return std::unexpected(extracted->error());
        auto& document = **extracted;
        stat.format = document.format;
        stat.omitted = document.omitted;
        if (!document.documents.empty()) stat.pages = document.documents.front().pages;
        for (const auto& block : document.blocks) {
            stat.characters += static_cast<std::size_t>(std::ranges::count_if(
                block.text, [](unsigned char c) { return (c & 0xC0U) != 0x80U; }));
        }
        auto assembled = assemble(std::move(document), index, remaining);
        if (!assembled) return std::unexpected(assembled.error());
        projected.emplace(Key{file.message, file.part}, std::move(*assembled));
    }
    core::PromptDocumentBuilder builder;
    std::vector<FileLocation> locations;
    std::vector<core::SensitiveText> parts;
    std::uint32_t message = 0;
    std::uint32_t segment_index = 0;
    std::optional<core::MessageRole> role;
    const auto flush = [&] {
        if (role) builder.add_message(*role, request.document.content_form(message), std::move(parts));
        parts.clear();
    };
    for (const auto& segment : request.document.segments()) {
        const auto source = segment.source();
        if (const auto* at = std::get_if<core::MessageSource>(&source)) {
            if (at->message != message) {
                flush();
                message = at->message;
            }
            role = at->role;
            const auto found = projected.find({at->message, at->part});
            if (found == projected.end()) {
                parts.push_back(core::SensitiveText::copy_of(segment.text()));
                ++segment_index;
            } else {
                for (auto& part : found->second) {
                    for (auto& location : part.locations) {
                        locations.push_back({location.file, location.document, location.block,
                                             core::SegmentIndex{segment_index}, location.span,
                                             std::move(location.where)});
                    }
                    parts.push_back(std::move(part.text));
                    ++segment_index;
                }
            }
        }
    }
    flush();
    for (const auto& segment : request.document.segments()) {
        if (std::holds_alternative<core::StopSource>(segment.source())) {
            builder.add_stop(core::SensitiveText::copy_of(segment.text()));
        }
    }
    auto document = std::move(builder).build(core::DocumentKind::ExtractedFiles);
    if (!document) return std::unexpected(document.error());
    return ResolvedDocuments{std::move(*document), std::move(locations)};
}

}  // namespace prompt_airlock::gateway
