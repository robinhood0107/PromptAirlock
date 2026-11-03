// PDF 글자 층(ADR 0028, 결정 #229). PDF 는 시험 안에서 만든다. PDFium 없이 빌드하면 PDF 는 unsupported 여야 한다.
// 한글·CID 글꼴·암호 PDF 는 받은 문서 측정(#227 과 11.5-2 측정 이슈)이 본다.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "prompt_airlock/extract/document.hpp"

namespace ex = prompt_airlock::extract;

namespace {

// 객체 목록으로 PDF 를 만든다(xref 위치를 계산).
std::string make_pdf(const std::vector<std::string>& objects) {
    std::string out = "%PDF-1.4\n";
    std::vector<std::size_t> offsets;
    for (std::size_t i = 0; i < objects.size(); ++i) {
        offsets.push_back(out.size());
        out += std::to_string(i + 1) + " 0 obj\n" + objects[i] + "\nendobj\n";
    }
    const auto xref = out.size();
    out += "xref\n0 " + std::to_string(objects.size() + 1) + "\n0000000000 65535 f \n";
    for (const auto o : offsets) {
        const auto n = std::to_string(o);
        out += std::string(10 - n.size(), '0') + n + " 00000 n \n";
    }
    out += "trailer\n<< /Size " + std::to_string(objects.size() + 1) + " /Root 1 0 R >>\nstartxref\n" +
           std::to_string(xref) + "\n%%EOF\n";
    return out;
}

std::string page_pdf(const std::string& content, const std::string& annots = "") {
    return make_pdf({
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        "/Resources << /Font << /F1 5 0 R >> >> " + annots + ">>",
        "<< /Length " + std::to_string(content.size()) + " >>\nstream\n" + content + "\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    });
}

auto run(const std::string& bytes) { return ex::extract(std::as_bytes(std::span(bytes.data(), bytes.size())), "pdf"); }

}  // namespace

#ifdef PA_TEST_WITH_PDFIUM
TEST(ExtractPdf, PageTextAndAnnotations) {
    const auto doc = run(page_pdf("BT /F1 12 Tf 72 712 Td (Contract 2026) Tj ET",
                                  "/Annots [<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (memo) >>]"));
    ASSERT_TRUE(doc) << ex::error_name(doc.error());
    EXPECT_EQ(doc->format, ex::DocumentFormat::Pdf);
    ASSERT_EQ(doc->blocks.size(), 1U);
    EXPECT_EQ(doc->blocks[0].where, "page1");
    EXPECT_EQ(doc->blocks[0].text, "Contract 2026");
    EXPECT_EQ(doc->omitted.comments, 1U);
}

TEST(ExtractPdf, ScannedAndBrokenFiles) {
    // 글자 그리기 없는 쪽(스캔본과 같음)
    EXPECT_EQ(run(page_pdf("0 0 1 rg 10 10 100 100 re f")).error(), ex::ExtractError::NoText);
    EXPECT_EQ(run("%PDF-1.7\nnot a pdf").error(), ex::ExtractError::Damaged);
    const auto whole = page_pdf("BT /F1 12 Tf 72 712 Td (x) Tj ET");
    EXPECT_FALSE(run(whole.substr(0, whole.size() / 3)));
}
#else
TEST(ExtractPdf, UnsupportedWithoutPdfium) {
    EXPECT_EQ(run(page_pdf("BT /F1 12 Tf 72 712 Td (x) Tj ET")).error(), ex::ExtractError::Unsupported);
}
#endif
