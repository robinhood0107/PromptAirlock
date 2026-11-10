// PDF 글자 층(PDFium C API, 결정 #229). 쪽마다 글자를 뽑고, 채운 양식 칸(글자·목록 칸) 값도 뽑는다(결정 #235).
// 메모 같은 주석은 세기만 하고, 숨긴 양식 칸은 숨긴 부분으로 센다. 링크·팝업은 메모가 아니므로 세지 않는다.
// 빈 사용자 암호로 열리는 암호 PDF 는 읽고, 암호가 필요하거나 모르는 보안 처리기면 Encrypted.
// 글자가 하나도 없으면(스캔본) 위에서 NoText 가 된다. PDFium 없이 빌드하면 PDF 는 Unsupported.
#include "detail.hpp"

#ifdef PA_WITH_PDFIUM
#include <fpdf_annot.h>
#include <fpdf_formfill.h>
#include <fpdf_edit.h>
#include <fpdf_text.h>
#include <fpdfview.h>

#include <algorithm>
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
// 단서 없이 줄이 끊긴 번호·이메일(로드맵 11.5-4): 앞 줄 끝이 쪽 글자의 오른쪽 끝까지 차고 다음 줄이 왼쪽 끝에서 시작하면
// 문단 안 자동 줄넘김으로 보고, 양쪽 글자가 번호·주소 글자일 때만 줄바꿈을 지운다. 표 칸은 오른쪽 끝에 닿지 않아 잇지 않는다.
std::vector<bool> soft_wraps(fpdf_textpage_t__* text, int count) {
    struct Box {
        double left = 0, right = 0, bottom = 0, top = 0;
    };
    const auto size = static_cast<std::size_t>(count);
    std::vector<Box> boxes(size);
    std::vector<bool> real(size, false);
    double page_left = 1e9;
    double page_right = -1e9;
    for (int i = 0; i < count; ++i) {
        auto& b = boxes[static_cast<std::size_t>(i)];
        const auto c = FPDFText_GetUnicode(text, i);
        if (FPDFText_IsGenerated(text, i) == 1 || c == ' ' || c == '\r' || c == '\n' ||
            !FPDFText_GetCharBox(text, i, &b.left, &b.right, &b.bottom, &b.top)) {
            continue;
        }
        real[static_cast<std::size_t>(i)] = true;
        page_left = std::min(page_left, b.left);
        page_right = std::max(page_right, b.right);
    }
    const auto joinable = [&](int i) {
        const auto c = FPDFText_GetUnicode(text, i);
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '@' || c == '.' ||
               c == '-' || c == '_';
    };
    std::vector<bool> skip(size, false);
    for (int i = 0; i < count; ++i) {
        const auto c = FPDFText_GetUnicode(text, i);
        if (real[static_cast<std::size_t>(i)] || (c != '\r' && c != '\n')) continue;
        int p = i - 1;
        while (p >= 0 && !real[static_cast<std::size_t>(p)]) --p;
        int n = i + 1;
        while (n < count && !real[static_cast<std::size_t>(n)]) ++n;
        if (p < 0 || n >= count || !joinable(p) || !joinable(n)) continue;
        const auto& a = boxes[static_cast<std::size_t>(p)];
        const auto& b = boxes[static_cast<std::size_t>(n)];
        const double tolerance = 1.5 * std::max(a.right - a.left, b.right - b.left);  // 글자 하나 반 너비
        if (b.top > a.bottom || page_right - a.right > tolerance || b.left - page_left > tolerance) continue;
        for (int k = p + 1; k < n; ++k) skip[static_cast<std::size_t>(k)] = true;
    }
    return skip;
}

std::string page_text(fpdf_textpage_t__* text, int count) {
    const auto skip = soft_wraps(text, count);
    std::string out;
    append_utf16(
        out,
        [&](std::size_t k) -> char32_t {
            const int index = static_cast<int>(k);
            if (skip[k]) return U'\r';  // append_utf16 이 CR 을 버린다.
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
        const auto saved_region = context.region;
        context.region = ++context.next_region;
        auto added = context.add("page" + std::to_string(page_number) + " field" + std::to_string(++field),
                                 std::move(utf8));
        context.region = saved_region;
        if (!added) return added;
    }
    return {};
}

}  // namespace

std::expected<void, ExtractError> extract_pdf(std::span<const std::byte> file, Context& context) {
    init_once();
    const auto first_block = context.doc.blocks.size();
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
    context.doc.documents[context.document].pages = static_cast<std::uint32_t>(pages);
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
        const int objects = FPDFPage_CountObjects(page.get());
        if (objects < 0) return std::unexpected(ExtractError::Damaged);
        for (int object = 0; object < objects; ++object) {
            const auto part = FPDFPage_GetObject(page.get(), object);
            if (!part) return std::unexpected(ExtractError::Damaged);
            if (FPDFPageObj_GetType(part) != FPDF_PAGEOBJ_TEXT) {
                if (context.doc.omitted.other_parts == UINT32_MAX) return std::unexpected(ExtractError::TooLarge);
                ++context.doc.omitted.other_parts;
            }
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
    // 양식 칸은 본문 흐름 뒤에 둔다. 칸 때문에 쪽 사이 본문이 잘리지 않게 한다.
    std::stable_partition(context.doc.blocks.begin() + static_cast<std::ptrdiff_t>(first_block),
                          context.doc.blocks.end(), [](const TextBlock& block) { return block.region == 0; });
    return {};
}
#else
std::expected<void, ExtractError> extract_pdf(std::span<const std::byte>, Context&) {
    return std::unexpected(ExtractError::Unsupported);
}
#endif

}  // namespace prompt_airlock::extract::detail
