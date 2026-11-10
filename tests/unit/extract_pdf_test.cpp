// PDF 글자 층(ADR 0028, 결정 #229). PDF 는 시험 안에서 만든다. PDFium 없이 빌드하면 PDF 는 unsupported 여야 한다.
// 한글·CID 글꼴·암호 PDF 는 받은 문서 측정(#227 과 11.5-2 측정 이슈)이 본다.
#include <gtest/gtest.h>
#include "pdf_writer.hpp"

#include <string>
#include <vector>

#include "prompt_airlock/extract/document.hpp"

namespace ex = prompt_airlock::extract;

namespace {

using pa_test::pdf::make_pdf;
using pa_test::pdf::page_pdf;

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

// 줄 끝 하이픈(#234): PDFium 은 하이픈과 줄바꿈을 지우고 표시해 둔다. 하이픈을 되돌려 번호·주소가 붙지 않게 한다.
TEST(ExtractPdf, LineEndHyphenIsKept) {
    const auto doc = run(page_pdf("BT /F1 12 Tf 72 712 Td (Account-) Tj 0 -14 Td (2026) Tj ET"));
    ASSERT_TRUE(doc) << ex::error_name(doc.error());
    EXPECT_EQ(doc->blocks.at(0).text, "Account-2026");
}

// 단서 없이 번호·주소가 줄 끝에서 끊기면(앞 줄이 오른쪽 끝까지, 다음 줄이 왼쪽 끝에서) 잇는다.
TEST(ExtractPdf, SoftWrappedNumberAndEmailAreJoined) {
    const auto doc = run(page_pdf("BT /F1 12 Tf 72 712 Td (Resident number 900101) Tj 0 -14 Td (1234567 next) Tj "
                                  "0 -14 Td (Mail to kim@mail.) Tj 0 -14 Td (example.org) Tj ET"));
    ASSERT_TRUE(doc) << ex::error_name(doc.error());
    const auto& text = doc->blocks.at(0).text;
    EXPECT_NE(text.find("Resident number 9001011234567 next"), std::string::npos) << text;
    EXPECT_NE(text.find("kim@mail.\nexample.org"), std::string::npos) << text;  // 오른쪽 끝에 닿지 않은 줄
}

// 표 칸처럼 오른쪽 끝에 닿지 않은 줄은 잇지 않는다.
TEST(ExtractPdf, ShortLinesAreNotJoined) {
    const auto doc = run(page_pdf("BT /F1 12 Tf 72 712 Td (900101) Tj 0 -14 Td (1234567) Tj "
                                  "0 -14 Td (a much longer line that sets the right edge) Tj ET"));
    ASSERT_TRUE(doc) << ex::error_name(doc.error());
    EXPECT_EQ(doc->blocks.at(0).text.find("9001011234567"), std::string::npos);
    EXPECT_NE(doc->blocks.at(0).text.find("900101\n1234567"), std::string::npos);
}

// 채운 양식 칸 값은 뽑고(결정 #235), 링크는 메모로 세지 않는다. 숨긴 칸은 숨긴 부분으로 센다.
TEST(ExtractPdf, FormFieldValues) {
    const std::string ap = "BT /F1 12 Tf 2 2 Td (900101-1234567) Tj ET";
    const auto field = [](const std::string& name, const std::string& flags) {
        return "<< /Type /Annot /Subtype /Widget /FT /Tx /T (" + name + ") /V (900101-1234567) /Rect [72 600 300 620] " +
               flags + "/P 3 0 R /AP << /N 7 0 R >> >>";
    };
    const auto doc = run(make_pdf({
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R 8 0 R] >> >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> "
        "/Annots [6 0 R 8 0 R 9 0 R] >>",
        "<< /Length 38 >>\nstream\nBT /F1 12 Tf 72 712 Td (Name field) Tj ET\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        field("rrn", ""),
        "<< /Type /XObject /Subtype /Form /BBox [0 0 228 20] /Resources << /Font << /F1 5 0 R >> >> /Length " +
            std::to_string(ap.size()) + " >>\nstream\n" + ap + "\nendstream",
        field("hidden", "/F 2 "),
        "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI (https://example.com) >> >>",
    }));
    ASSERT_TRUE(doc) << ex::error_name(doc.error());
    ASSERT_EQ(doc->blocks.size(), 2U);
    EXPECT_EQ(doc->blocks[1].where, "page1 field1");
    EXPECT_EQ(doc->blocks[1].text, "900101-1234567");
    EXPECT_EQ(doc->omitted.comments, 0U);
    EXPECT_EQ(doc->omitted.hidden, 1U);
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
