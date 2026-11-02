// 추출 자식과 부모가 주고받는 JSON(버전 1). 구조체 메모리를 그대로 보내지 않는다.
// {"v":1,"ok":true,"format":"docx","blocks":[{"at":"p1","text":"..."}],"omitted":{"comments":0,...}}
// {"v":1,"ok":false,"error":"encrypted"}
#include <nlohmann/json.hpp>

#include <array>
#include <utility>

#include "prompt_airlock/extract/runner.hpp"

namespace prompt_airlock::extract {
namespace {

using json = nlohmann::json;

constexpr std::array<DocumentFormat, 12> all_formats = {
    DocumentFormat::Text, DocumentFormat::Csv,  DocumentFormat::Markdown, DocumentFormat::Html,  DocumentFormat::Docx,
    DocumentFormat::Xlsx, DocumentFormat::Pptx, DocumentFormat::Hwpx,     DocumentFormat::Hwpml, DocumentFormat::Hwp,
    DocumentFormat::Pdf,  DocumentFormat::Zip,
};
constexpr std::array<ExtractError, 8> all_errors = {
    ExtractError::TooLarge,  ExtractError::UnknownFormat, ExtractError::LegacyFormat, ExtractError::Unsupported,
    ExtractError::Encrypted, ExtractError::Damaged,       ExtractError::Bomb,         ExtractError::NoText,
};

}  // namespace

std::string_view format_name(DocumentFormat format) noexcept {
    switch (format) {
        case DocumentFormat::Text: return "txt";
        case DocumentFormat::Csv: return "csv";
        case DocumentFormat::Markdown: return "md";
        case DocumentFormat::Html: return "htm";
        case DocumentFormat::Docx: return "docx";
        case DocumentFormat::Xlsx: return "xlsx";
        case DocumentFormat::Pptx: return "pptx";
        case DocumentFormat::Hwpx: return "hwpx";
        case DocumentFormat::Hwpml: return "hwpml";
        case DocumentFormat::Hwp: return "hwp";
        case DocumentFormat::Pdf: return "pdf";
        case DocumentFormat::Zip: return "zip";
    }
    return "invalid";
}

std::string_view error_name(ExtractError error) noexcept {
    switch (error) {
        case ExtractError::TooLarge: return "too_large";
        case ExtractError::UnknownFormat: return "unknown_format";
        case ExtractError::LegacyFormat: return "legacy_format";
        case ExtractError::Unsupported: return "unsupported";
        case ExtractError::Encrypted: return "encrypted";
        case ExtractError::Damaged: return "damaged";
        case ExtractError::Bomb: return "bomb";
        case ExtractError::NoText: return "no_text";
    }
    return "invalid";
}

std::string_view run_error_name(RunError error) noexcept {
    switch (error) {
        case RunError::StartFailed: return "start_failed";
        case RunError::Timeout: return "timeout";
        case RunError::OutputTooLarge: return "output_too_large";
        case RunError::Crashed: return "crashed";
        case RunError::BadOutput: return "bad_output";
        case RunError::Cancelled: return "cancelled";
    }
    return "invalid";
}

std::string to_json(const std::expected<ExtractedDocument, ExtractError>& result) {
    json out = {{"v", protocol_version}, {"ok", result.has_value()}};
    if (!result) {
        out["error"] = error_name(result.error());
    } else {
        out["format"] = format_name(result->format);
        json blocks = json::array();
        for (const auto& b : result->blocks) {
            blocks.push_back({{"at", b.where}, {"text", b.text}});
        }
        out["blocks"] = std::move(blocks);
        const auto& o = result->omitted;
        out["omitted"] = {{"comments", o.comments}, {"revisions", o.revisions}, {"hidden", o.hidden},
                          {"other_parts", o.other_parts}};
    }
    // 글자는 모두 UTF-8 로 만들었다. 그래도 아니면 예외 대신 손상으로 알린다.
    try {
        return out.dump();
    } catch (const json::exception&) {
        return json{{"v", protocol_version}, {"ok", false}, {"error", error_name(ExtractError::Damaged)}}.dump();
    }
}

std::expected<std::expected<ExtractedDocument, ExtractError>, RunError> from_json(std::string_view text) {
    const auto bad = std::unexpected(RunError::BadOutput);
    const json in = json::parse(text, nullptr, false);
    if (in.is_discarded() || !in.is_object() || in.value("v", 0) != protocol_version || !in.contains("ok") ||
        !in["ok"].is_boolean()) {
        return bad;
    }
    if (!in["ok"].get<bool>()) {
        if (!in.contains("error") || !in["error"].is_string()) {
            return bad;
        }
        for (const auto e : all_errors) {
            if (error_name(e) == in["error"].get_ref<const std::string&>()) {
                return std::expected<ExtractedDocument, ExtractError>(std::unexpected(e));
            }
        }
        return bad;
    }
    ExtractedDocument doc;
    const auto format = in.find("format");
    const auto blocks = in.find("blocks");
    const auto omitted = in.find("omitted");
    if (format == in.end() || !format->is_string() || blocks == in.end() || !blocks->is_array() ||
        omitted == in.end() || !omitted->is_object()) {
        return bad;
    }
    bool known = false;
    for (const auto f : all_formats) {
        if (format_name(f) == format->get_ref<const std::string&>()) {
            doc.format = f;
            known = true;
        }
    }
    if (!known) {
        return bad;
    }
    for (const auto& b : *blocks) {
        if (!b.is_object() || !b.contains("at") || !b["at"].is_string() || !b.contains("text") || !b["text"].is_string()) {
            return bad;
        }
        doc.blocks.push_back({b["at"].get<std::string>(), b["text"].get<std::string>()});
    }
    const auto count = [&](const char* key, std::uint32_t& out) {
        const auto it = omitted->find(key);
        if (it == omitted->end() || !it->is_number_unsigned()) {
            return false;
        }
        out = it->get<std::uint32_t>();
        return true;
    };
    if (!count("comments", doc.omitted.comments) || !count("revisions", doc.omitted.revisions) ||
        !count("hidden", doc.omitted.hidden) || !count("other_parts", doc.omitted.other_parts)) {
        return bad;
    }
    return doc;
}

}  // namespace prompt_airlock::extract
