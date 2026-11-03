// 형식 판별과 나누기. 형식은 파일 앞 byte(매직)와 zip 안 항목으로 정하고, 이름 확장자는 글자 형식을 가를 때만 쓴다.
#include <algorithm>
#include <array>

#include "detail.hpp"

namespace prompt_airlock::extract {
namespace detail {
namespace {

[[nodiscard]] std::string lower(std::string_view s) {
    std::string out(s);
    std::ranges::transform(out, out.begin(), [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c; });
    return out;
}

[[nodiscard]] std::string extension(std::string_view name) {
    const auto dot = name.rfind('.');
    const auto slash = name.rfind('/');
    if (dot == std::string_view::npos || (slash != std::string_view::npos && dot < slash)) {
        return {};
    }
    return lower(name.substr(dot + 1));
}

// zip 안에서 해석하는 항목 확장자. 나머지(그림 등)는 세기만 한다.
constexpr std::array<std::string_view, 13> known_entries = {"txt", "csv", "md", "htm", "html", "hwpx", "docx",
                                                            "xlsx", "pptx", "zip", "hwp", "pdf", "doc"};

[[nodiscard]] bool looks_html(std::string_view text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) {
        return false;
    }
    const auto head = lower(text.substr(first, 14));
    return head.starts_with("<!doctype html") || head.starts_with("<html");
}

[[nodiscard]] std::expected<DocumentFormat, ExtractError> extract_text(std::span<const std::byte> file,
                                                                      std::string_view hint, Context& context) {
    auto text = decode_text(file);
    if (!text) {
        return std::unexpected(text.error());
    }
    // XML 은 마크업째 보내지 않는다. 한글 XML(HWPML)은 본문 글자만 뽑고, 다른 XML 은 아직 받지 않는다.
    const auto first = text->find_first_not_of(" \t\r\n");
    if (first != std::string::npos && std::string_view(*text).substr(first).starts_with("<?xml")) {
        if (text->find("<HWPML") == std::string::npos) {
            return std::unexpected(ExtractError::Unsupported);
        }
        auto r = extract_hwpml(*text, context);
        return r ? std::expected<DocumentFormat, ExtractError>(DocumentFormat::Hwpml) : std::unexpected(r.error());
    }
    const bool html = hint == "htm" || hint == "html" || ((hint.empty() || hint == "txt") && looks_html(*text));
    const auto format = html ? DocumentFormat::Html
                        : hint == "csv" ? DocumentFormat::Csv
                        : hint == "md"  ? DocumentFormat::Markdown
                                        : DocumentFormat::Text;
    const std::string label = format == DocumentFormat::Csv ? "row" : "line";
    if (html) {
        std::size_t n = 0;
        for (auto& line : html_lines(*text)) {
            if (auto r = context.add(label + std::to_string(++n), std::move(line)); !r) {
                return std::unexpected(r.error());
            }
        }
        return format;
    }
    std::size_t n = 0;
    std::size_t start = 0;
    const std::string_view all = *text;
    while (start < all.size()) {
        auto end = all.find('\n', start);
        if (end == std::string_view::npos) {
            end = all.size();
        }
        auto line = all.substr(start, end - start);
        if (line.ends_with('\r')) {
            line.remove_suffix(1);
        }
        ++n;
        if (auto r = context.add(label + std::to_string(n), std::string(line)); !r) {
            return std::unexpected(r.error());
        }
        start = end + 1;
    }
    return format;
}

[[nodiscard]] std::expected<void, ExtractError> extract_container(const Zip& zip, std::size_t depth,
                                                                 Context& context) {
    if (depth >= context.limits.depth) {
        return std::unexpected(ExtractError::Bomb);
    }
    for (const auto& name : zip.names()) {
        const auto ext = extension(name);
        if (std::ranges::find(known_entries, ext) == known_entries.end()) {
            ++context.doc.omitted.other_parts;
            continue;
        }
        if (++context.nested > context.limits.nested_documents) {
            return std::unexpected(ExtractError::Bomb);
        }
        auto bytes = zip.read(name, context);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        const auto saved = context.prefix;
        context.prefix += name + ":";
        auto inner = extract_into(std::as_bytes(std::span(*bytes)), ext, depth + 1, context);
        context.prefix = saved;
        if (!inner) {
            return std::unexpected(inner.error());  // 안의 문서 하나라도 못 읽으면 전체를 거절한다(빠뜨리고 보내지 않음)
        }
    }
    return {};
}

}  // namespace

std::expected<DocumentFormat, ExtractError> extract_into(std::span<const std::byte> file, std::string_view hint,
                                                        std::size_t depth, Context& context) {
    const std::string_view head(reinterpret_cast<const char*>(file.data()), std::min<std::size_t>(file.size(), 8));
    if (head.starts_with("PK\x03\x04") || head.starts_with("PK\x05\x06")) {
        auto zip = Zip::open(file, context);
        if (!zip) {
            return std::unexpected(zip.error());
        }
        if (zip->contains("mimetype")) {
            auto mime = zip->read("mimetype", context);
            if (!mime) {
                return std::unexpected(mime.error());
            }
            if (mime->starts_with("application/hwp+zip")) {
                auto r = extract_hwpx(*zip, context);
                return r ? std::expected<DocumentFormat, ExtractError>(DocumentFormat::Hwpx) : std::unexpected(r.error());
            }
        }
        struct Office {
            std::string_view part;
            DocumentFormat format;
            std::expected<void, ExtractError> (*run)(const Zip&, Context&);
        };
        for (const auto& o : {Office{"word/document.xml", DocumentFormat::Docx, extract_docx},
                              Office{"xl/workbook.xml", DocumentFormat::Xlsx, extract_xlsx},
                              Office{"ppt/presentation.xml", DocumentFormat::Pptx, extract_pptx}}) {
            if (zip->contains(o.part)) {
                auto r = o.run(*zip, context);
                return r ? std::expected<DocumentFormat, ExtractError>(o.format) : std::unexpected(r.error());
            }
        }
        auto r = extract_container(*zip, depth, context);
        return r ? std::expected<DocumentFormat, ExtractError>(DocumentFormat::Zip) : std::unexpected(r.error());
    }
    if (head.starts_with("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")) {
        // 복합 문서(CFB): FileHeader 스트림이 있으면 hwp, 없으면 doc·xls·ppt 같은 옛 형식으로 거절한다.
        auto cfb = Cfb::open(file, context);
        if (!cfb) {
            return std::unexpected(cfb.error());
        }
        if (!cfb->contains("FileHeader")) {
            return std::unexpected(ExtractError::LegacyFormat);
        }
        auto r = extract_hwp(*cfb, context);
        return r ? std::expected<DocumentFormat, ExtractError>(DocumentFormat::Hwp) : std::unexpected(r.error());
    }
    if (head.starts_with("%PDF-")) {
        auto r = extract_pdf(file, context);
        return r ? std::expected<DocumentFormat, ExtractError>(DocumentFormat::Pdf) : std::unexpected(r.error());
    }
    return extract_text(file, hint, context);
}

}  // namespace detail

std::expected<ExtractedDocument, ExtractError> extract(std::span<const std::byte> file, std::string_view name_hint,
                                                      const ExtractLimits& limits) {
    if (file.size() > limits.file_bytes) {
        return std::unexpected(ExtractError::TooLarge);
    }
    ExtractedDocument doc;
    detail::Context context{limits, doc, 0, 0, 0, {}};
    const auto format = detail::extract_into(file, name_hint, 0, context);
    if (!format) {
        return std::unexpected(format.error());
    }
    if (doc.blocks.empty()) {
        return std::unexpected(ExtractError::NoText);
    }
    doc.format = *format;
    return doc;
}

}  // namespace prompt_airlock::extract
