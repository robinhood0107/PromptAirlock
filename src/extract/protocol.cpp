// 추출 자식과 부모가 주고받는 JSON(버전 2). 구조체 메모리를 그대로 보내지 않는다.
// v2 성공에는 documents(형식·쪽 수), blocks(문서·영역·위치·글자), omitted를 모두 담는다.
// {"v":2,"ok":false,"error":"encrypted"}
#include <nlohmann/json.hpp>

#include <array>
#include <utility>
#include <set>
#include <stdexcept>

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
        out["documents"] = json::array();
        const auto add_document = [&](const DocumentInfo& info) {
            out["documents"].push_back({{"format", format_name(info.format)},
                                       {"pages", info.pages ? json(*info.pages) : json(nullptr)}});
        };
        if (result->documents.empty()) add_document({result->format, std::nullopt});
        for (const auto& info : result->documents) add_document(info);
        out["blocks"] = json::array();
        for (const auto& b : result->blocks) {
            out["blocks"].push_back({{"at", b.where}, {"text", b.text}, {"document", b.document}, {"region", b.region}});
        }
        const auto& o = result->omitted;
        out["omitted"] = {{"comments", o.comments}, {"revisions", o.revisions}, {"hidden", o.hidden},
                          {"other_parts", o.other_parts}};
    }
    try {
        return out.dump();
    } catch (const json::exception&) {
        return json{{"v", protocol_version}, {"ok", false}, {"error", error_name(ExtractError::Damaged)}}.dump();
    }
}

std::expected<std::expected<ExtractedDocument, ExtractError>, RunError> from_json(std::string_view text) {
    const auto bad = std::unexpected(RunError::BadOutput);
    if (text.size() > RunLimits{}.output_bytes) return bad;
    try {
        std::vector<std::set<std::string>> keys;
        const auto check = [&](int depth, json::parse_event_t event, json& value) {
            if (depth > 16) throw std::invalid_argument("protocol depth");
            if (event == json::parse_event_t::object_start) keys.emplace_back();
            if (event == json::parse_event_t::key && !keys.back().insert(value.get<std::string>()).second)
                throw std::invalid_argument("protocol duplicate");
            if (event == json::parse_event_t::object_end) keys.pop_back();
            return true;
        };
        const json in = json::parse(text, check, false);
        if (!in.is_object() || !in.contains("v") || !in["v"].is_number_unsigned() ||
            in["v"].get<std::uint64_t>() != protocol_version || !in.contains("ok") || !in["ok"].is_boolean()) return bad;
        if (!in["ok"].get<bool>()) {
            if (in.size() != 3 || !in.contains("error") || !in["error"].is_string()) return bad;
            for (const auto e : all_errors) {
                if (error_name(e) == in["error"].get_ref<const std::string&>()) {
                    return std::expected<ExtractedDocument, ExtractError>(std::unexpected(e));
                }
            }
            return bad;
        }
        if (in.size() != 6 || !in.contains("format") || !in.contains("documents") ||
            !in.contains("blocks") || !in.contains("omitted")) return bad;
        const auto format = [](const json& value) -> std::optional<DocumentFormat> {
            if (!value.is_string()) return std::nullopt;
            for (const auto f : all_formats) if (format_name(f) == value.get_ref<const std::string&>()) return f;
            return std::nullopt;
        };
        const auto root_format = format(in["format"]);
        if (!root_format || !in["documents"].is_array() || in["documents"].empty() ||
            in["documents"].size() > ExtractLimits{}.nested_documents + 1 ||
            !in["blocks"].is_array() || !in["omitted"].is_object() || in["omitted"].size() != 4) return bad;
        ExtractedDocument doc;
        doc.format = *root_format;
        for (const auto& value : in["documents"]) {
            if (!value.is_object() || value.size() != 2 || !value.contains("format") || !value.contains("pages")) return bad;
            const auto f = format(value["format"]);
            if (!f) return bad;
            DocumentInfo info{*f, std::nullopt};
            if (!value["pages"].is_null()) {
                if (!value["pages"].is_number_unsigned() ||
                    value["pages"].get<std::uint64_t>() > ExtractLimits{}.pdf_pages) return bad;
                info.pages = value["pages"].get<std::uint32_t>();
            }
            doc.documents.push_back(info);
        }
        if (doc.documents.front().format != doc.format) return bad;
        std::size_t output = 0;
        for (const auto& b : in["blocks"]) {
            if (!b.is_object() || b.size() != 4 || !b.contains("at") || !b["at"].is_string() ||
                !b.contains("text") || !b["text"].is_string() || !b.contains("document") ||
                !b["document"].is_number_unsigned() || !b.contains("region") || !b["region"].is_number_unsigned() ||
                b["document"].get<std::uint64_t>() >= doc.documents.size() ||
                b["region"].get<std::uint64_t>() > UINT32_MAX) return bad;
            const auto& content = b["text"].get_ref<const std::string&>();
            if (content.size() > ExtractLimits{}.output_bytes - output) return bad;
            output += content.size();
            doc.blocks.push_back({b["at"].get<std::string>(), content, b["document"].get<std::uint32_t>(),
                                  b["region"].get<std::uint32_t>()});
        }
        if (doc.blocks.empty()) return bad;
        const auto count = [&](const char* key, std::uint32_t& out) {
            const auto it = in["omitted"].find(key);
            if (it == in["omitted"].end() || !it->is_number_unsigned() ||
                it->get<std::uint64_t>() > UINT32_MAX) return false;
            out = it->get<std::uint32_t>();
            return true;
        };
        if (!count("comments", doc.omitted.comments) || !count("revisions", doc.omitted.revisions) ||
            !count("hidden", doc.omitted.hidden) || !count("other_parts", doc.omitted.other_parts)) return bad;
        return doc;
    } catch (const std::exception&) {
        return bad;
    }
}

}  // namespace prompt_airlock::extract
