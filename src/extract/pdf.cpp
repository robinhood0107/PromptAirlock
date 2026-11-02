// PDF 글자 층(PDFium C API, 결정 #229). 쪽마다 글자를 뽑고, 주석(메모)은 세기만 한다.
// 빈 사용자 암호로 열리는 암호 PDF 는 읽고, 암호가 필요하거나 모르는 보안 처리기면 Encrypted.
// 글자가 하나도 없으면(스캔본) 위에서 NoText 가 된다. PDFium 없이 빌드하면 PDF 는 Unsupported.
#include "detail.hpp"

#ifdef PA_WITH_PDFIUM
#include <fpdf_annot.h>
#include <fpdf_text.h>
#include <fpdfview.h>

#include <memory>
#include <vector>
#endif

namespace prompt_airlock::extract::detail {

#ifdef PA_WITH_PDFIUM
namespace {

struct DocumentCloser {
    void operator()(fpdf_document_t__* d) const noexcept { FPDF_CloseDocument(d); }
};
struct PageCloser {
    void operator()(fpdf_page_t__* p) const noexcept { FPDF_ClosePage(p); }
};
struct TextCloser {
    void operator()(fpdf_textpage_t__* t) const noexcept { FPDFText_ClosePage(t); }
};

void init_once() {
    // 추출 프로세스 하나에서 한 번만. 프로세스가 끝날 때 함께 정리된다.
    static const bool done = [] {
        FPDF_LIBRARY_CONFIG config{};
        config.version = 2;
        FPDF_InitLibraryWithConfig(&config);
        return true;
    }();
    (void)done;
}

}  // namespace

std::expected<void, ExtractError> extract_pdf(std::span<const std::byte> file, Context& context) {
    init_once();
    const std::unique_ptr<fpdf_document_t__, DocumentCloser> doc(
        FPDF_LoadMemDocument64(file.data(), file.size(), nullptr));
    if (!doc) {
        const auto e = FPDF_GetLastError();
        return std::unexpected(e == FPDF_ERR_PASSWORD || e == FPDF_ERR_SECURITY ? ExtractError::Encrypted
                                                                                 : ExtractError::Damaged);
    }
    const int pages = FPDF_GetPageCount(doc.get());
    if (pages < 0 || static_cast<std::size_t>(pages) > context.limits.pdf_pages) {
        return std::unexpected(pages < 0 ? ExtractError::Damaged : ExtractError::TooLarge);
    }
    for (int i = 0; i < pages; ++i) {
        const std::unique_ptr<fpdf_page_t__, PageCloser> page(FPDF_LoadPage(doc.get(), i));
        if (!page) {
            return std::unexpected(ExtractError::Damaged);
        }
        context.doc.omitted.comments += static_cast<std::uint32_t>(std::max(0, FPDFPage_GetAnnotCount(page.get())));
        const std::unique_ptr<fpdf_textpage_t__, TextCloser> text(FPDFText_LoadPage(page.get()));
        if (!text) {
            return std::unexpected(ExtractError::Damaged);
        }
        const int count = FPDFText_CountChars(text.get());
        if (count <= 0) {
            continue;
        }
        std::vector<unsigned short> units(static_cast<std::size_t>(count) + 1, 0);
        const int got = FPDFText_GetText(text.get(), 0, count, units.data());
        std::string utf8;
        for (int k = 0; k + 1 < got; ++k) {  // got 은 끝 NUL 을 포함한다
            char32_t c = units[static_cast<std::size_t>(k)];
            if (c >= 0xD800 && c <= 0xDBFF && k + 2 < got) {
                const char32_t low = units[static_cast<std::size_t>(k) + 1];
                if (low >= 0xDC00 && low <= 0xDFFF) {
                    c = 0x10000 + ((c - 0xD800) << 10) + (low - 0xDC00);
                    ++k;
                }
            }
            if (c >= 0xD800 && c <= 0xDFFF) {
                c = 0xFFFD;  // 짝 없는 대리 쌍(글꼴 대응표 오류)은 대체 문자로
            }
            if (c == U'\r') {
                continue;
            }
            append_utf8(utf8, c == 0 ? U' ' : c);
        }
        if (auto r = context.add("page" + std::to_string(i + 1), std::move(utf8)); !r) {
            return r;
        }
    }
    return {};
}
#else
std::expected<void, ExtractError> extract_pdf(std::span<const std::byte>, Context&) {
    return std::unexpected(ExtractError::Unsupported);
}
#endif

}  // namespace prompt_airlock::extract::detail
