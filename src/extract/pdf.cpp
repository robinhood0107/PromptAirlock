// PDF 글자 층(PDFium C API, 결정 #229). 쪽마다 글자를 뽑고, 채운 양식 칸(글자·목록 칸) 값도 뽑는다(결정 #235).
// 메모 같은 주석은 세기만 하고, 숨긴 양식 칸은 숨긴 부분으로 센다. 링크·팝업은 메모가 아니므로 세지 않는다.
// 빈 사용자 암호로 열리는 암호 PDF 는 읽고, 암호가 필요하거나 모르는 보안 처리기면 Encrypted.
// 글자가 하나도 없으면(스캔본) 위에서 NoText 가 된다. PDFium 없이 빌드하면 PDF 는 Unsupported.
#include "detail.hpp"

#ifdef PA_WITH_PDFIUM
#include <fpdf_annot.h>
#include <fpdf_formfill.h>
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
struct FormCloser {
    void operator()(fpdf_form_handle_t__* f) const noexcept { FPDFDOC_ExitFormFillEnvironment(f); }
};
struct PageCloser {
    void operator()(fpdf_page_t__* p) const noexcept { FPDF_ClosePage(p); }
};
struct TextCloser {
    void operator()(fpdf_textpage_t__* t) const noexcept { FPDFText_ClosePage(t); }
};
struct AnnotCloser {
    void operator()(fpdf_annotation_t__* a) const noexcept { FPDFPage_CloseAnnot(a); }
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

// UTF-16 단위를 UTF-8 로. 짝 없는 대리 쌍(글꼴 대응표 오류)은 대체 문자로, CR 은 버린다.
template <class Unit>
void append_utf16(std::string& out, const Unit& unit, std::size_t n) {
    for (std::size_t k = 0; k < n; ++k) {
        char32_t c = unit(k);
        if (c >= 0xD800 && c <= 0xDBFF && k + 1 < n && unit(k + 1) >= 0xDC00 && unit(k + 1) <= 0xDFFF) {
            c = 0x10000 + ((c - 0xD800) << 10) + (unit(k + 1) - 0xDC00);
            ++k;
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            c = 0xFFFD;
        }
        if (c != U'\r') {
            append_utf8(out, c);
        }
    }
}

// 쪽 글자. 줄 끝 하이픈으로 이어진 낱말은 PDFium 이 하이픈과 줄바꿈을 지우고 표시해 두므로 하이픈을 되돌린다
// ("900101-" 줄바꿈 "1234567" 이 "9001011234567" 처럼 붙어 나오지 않게, #234). 대응표 없는 글자는 대체 문자로.
std::string page_text(fpdf_textpage_t__* text, int count) {
    std::string out;
    append_utf16(
        out,
        [&](std::size_t k) -> char32_t {
            const int index = static_cast<int>(k);
            if (FPDFText_IsHyphen(text, index) == 1) {
                return U'-';
            }
            const auto c = static_cast<char32_t>(FPDFText_GetUnicode(text, index));
            return c == 0 || c == 0xFFFE ? 0xFFFD : c;
        },
        static_cast<std::size_t>(count));
    return out;
}

// 쪽의 주석: 메모는 세고, 보이는 글자·목록 양식 칸은 값을 낸다(값 없는 칸, 체크 칸, 서명 칸은 뺌).
std::expected<void, ExtractError> page_annotations(fpdf_form_handle_t__* form, fpdf_page_t__* page, int page_number,
                                                   Context& context) {
    const int count = FPDFPage_GetAnnotCount(page);
    for (int a = 0, field = 0; a < count; ++a) {
        const std::unique_ptr<fpdf_annotation_t__, AnnotCloser> annot(FPDFPage_GetAnnot(page, a));
        if (!annot) {
            return std::unexpected(ExtractError::Damaged);
        }
        const auto subtype = FPDFAnnot_GetSubtype(annot.get());
        if (subtype == FPDF_ANNOT_LINK || subtype == FPDF_ANNOT_POPUP) {
            continue;
        }
        if (subtype != FPDF_ANNOT_WIDGET) {
            ++context.doc.omitted.comments;
            continue;
        }
        const auto type = form == nullptr ? -1 : FPDFAnnot_GetFormFieldType(form, annot.get());
        if (type != FPDF_FORMFIELD_TEXTFIELD && type != FPDF_FORMFIELD_COMBOBOX && type != FPDF_FORMFIELD_LISTBOX) {
            continue;
        }
        if ((FPDFAnnot_GetFlags(annot.get()) & (FPDF_ANNOT_FLAG_HIDDEN | FPDF_ANNOT_FLAG_INVISIBLE)) != 0) {
            ++context.doc.omitted.hidden;
            continue;
        }
        const auto bytes = FPDFAnnot_GetFormFieldValue(form, annot.get(), nullptr, 0);
        if (bytes <= 2) {
            continue;  // 빈 값("\0\0")
        }
        std::vector<FPDF_WCHAR> value(bytes / 2, 0);
        FPDFAnnot_GetFormFieldValue(form, annot.get(), value.data(), bytes);
        std::string utf8;
        append_utf16(utf8, [&](std::size_t k) -> char32_t { return value[k]; }, value.size() - 1);
        if (auto r = context.add("page" + std::to_string(page_number) + " field" + std::to_string(++field),
                                 std::move(utf8));
            !r) {
            return r;
        }
    }
    return {};
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
    // 양식 칸 값을 읽는 데만 쓴다. 콜백은 하나도 주지 않는다(PDFium 이 판 1 의 필수 콜백 없이도 값을 읽음).
    FPDF_FORMFILLINFO form_info{};
    form_info.version = 1;
    const std::unique_ptr<fpdf_form_handle_t__, FormCloser> form(
        FPDFDOC_InitFormFillEnvironment(doc.get(), &form_info));
    for (int i = 0; i < pages; ++i) {
        const std::unique_ptr<fpdf_page_t__, PageCloser> page(FPDF_LoadPage(doc.get(), i));
        if (!page) {
            return std::unexpected(ExtractError::Damaged);
        }
        const std::unique_ptr<fpdf_textpage_t__, TextCloser> text(FPDFText_LoadPage(page.get()));
        if (!text) {
            return std::unexpected(ExtractError::Damaged);
        }
        if (const int count = FPDFText_CountChars(text.get()); count > 0) {
            if (auto r = context.add("page" + std::to_string(i + 1), page_text(text.get(), count)); !r) {
                return r;
            }
        }
        if (auto r = page_annotations(form.get(), page.get(), i + 1, context); !r) {
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
