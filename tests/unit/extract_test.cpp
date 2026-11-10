// 문서 추출(ADR 0028): 글자 형식, docx·xlsx·pptx·hwpx, zip 묶음, 상한과 공격 입력, 주고받는 JSON.
// 문서는 시험 안에서 libzip 으로 만든다(바이너리 시험 파일을 저장소에 두지 않음). 내용은 모두 합성이다.
#include <gtest/gtest.h>
#include <zip.h>

#include <string>
#include <utility>
#include <vector>

#include "hwp_writer.hpp"
#include "document_writer.hpp"
#include "prompt_airlock/extract/document.hpp"
#include "prompt_airlock/extract/runner.hpp"

namespace ex = prompt_airlock::extract;

namespace {

using pa_test::documents::Entry;
using pa_test::documents::make_zip;
using pa_test::documents::docx;
using pa_test::documents::w;

std::expected<ex::ExtractedDocument, ex::ExtractError> run(std::string_view bytes, std::string_view hint = {},
                                                         const ex::ExtractLimits& limits = {}) {
    return ex::extract(std::as_bytes(std::span(bytes.data(), bytes.size())), hint, limits);
}

std::vector<std::string> texts(const ex::ExtractedDocument& doc) {
    std::vector<std::string> out;
    for (const auto& b : doc.blocks) {
        out.push_back(b.text);
    }
    return out;
}


}  // namespace

TEST(ExtractText, Encodings) {
    EXPECT_EQ(texts(*run("첫 줄\n\n둘째 줄\r\n")), (std::vector<std::string>{"첫 줄", "둘째 줄"}));
    EXPECT_EQ(texts(*run("\xEF\xBB\xBF가나")), std::vector<std::string>{"가나"});
    EXPECT_EQ(texts(*run(std::string("\xFF\xFE\x00\xAC", 4))), std::vector<std::string>{"가"});   // UTF-16LE
    EXPECT_EQ(texts(*run(std::string("\xFE\xFF\xAC\x00", 4))), std::vector<std::string>{"가"});   // UTF-16BE
    EXPECT_EQ(texts(*run("\xB0\xA1\x81\x41 ab")), std::vector<std::string>{"가갂 ab"});           // CP949(UHC 확장 포함)
    EXPECT_EQ(run("\xB0").error(), ex::ExtractError::UnknownFormat);                               // 잘린 CP949
    EXPECT_EQ(run("\xC9\xFE").error(), ex::ExtractError::UnknownFormat);                           // 사용자 정의 영역(UTF-8 아님)
    EXPECT_EQ(run(std::string("a\0b", 3)).error(), ex::ExtractError::UnknownFormat);
    EXPECT_EQ(run("   \n").error(), ex::ExtractError::NoText);
}

TEST(ExtractText, CsvAndHtml) {
    const auto csv = *run("이름,번호\n가,1\n", "csv");
    EXPECT_EQ(csv.format, ex::DocumentFormat::Csv);
    EXPECT_EQ(csv.blocks[2].where, "row2 cell1");
    const auto html = *run("<!DOCTYPE html><html><head><style>p{}</style><script>var x='비밀';</script></head>"
                           "<body><!-- 숨김 --><p>가 &amp; 나&#44;&#xAC00;</p><table><tr><td>a</td><td>b</td></tr>"
                           "</table></body></html>");
    EXPECT_EQ(html.format, ex::DocumentFormat::Html);
    EXPECT_EQ(texts(html), (std::vector<std::string>{"가 & 나,가", "| a\t| b\t |"}));
}

TEST(ExtractOffice, DocxBodyHiddenRevisionsAndComments) {
    const auto doc = run(docx(R"(<w:p><w:r><w:t>본문 </w:t></w:r><w:r><w:t>하나</w:t></w:r></w:p>)"
                              R"(<w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>숨긴 글</w:t></w:r><w:r><w:t>보임</w:t></w:r></w:p>)"
                              R"(<w:p><w:del><w:r><w:delText>지운 글</w:delText></w:r></w:del><w:ins><w:r><w:t>넣은 글</w:t></w:r></w:ins></w:p>)"
                              R"(<w:tbl><w:tr><w:tc><w:p><w:r><w:t>칸</w:t></w:r></w:p></w:tc></w:tr></w:tbl>)",
                              {{"word/comments.xml", "<w:comments " + w + "><w:comment w:id=\"0\"><w:p><w:r><w:t>메모</w:t></w:r></w:p></w:comment></w:comments>"},
                               {"word/header1.xml", "<w:hdr " + w + "/>"},
                               {"docProps/core.xml", "<cp/>"}}));
    ASSERT_TRUE(doc);
    EXPECT_EQ(doc->format, ex::DocumentFormat::Docx);
    EXPECT_EQ(texts(*doc), (std::vector<std::string>{"본문 하나", "보임", "넣은 글", "칸"}));
    EXPECT_EQ(doc->omitted, (ex::Omitted{.comments = 1, .revisions = 1, .hidden = 1, .other_parts = 2}));
}

TEST(ExtractOffice, XlsxSharedStringsHiddenSheetsAndRows) {
    const std::string ns = R"(xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="r")";
    const auto doc = run(make_zip({
        {"[Content_Types].xml", "<Types/>"},
        {"xl/workbook.xml", "<workbook " + ns + R"(><sheets><sheet name="보이는" sheetId="1" r:id="rId1"/>)"
                            R"(<sheet name="숨긴" sheetId="2" state="hidden" r:id="rId2"/></sheets></workbook>)"},
        {"xl/_rels/workbook.xml.rels", R"(<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/>)"
                                       R"(<Relationship Id="rId2" Target="/xl/worksheets/sheet2.xml"/></Relationships>)"},
        {"xl/sharedStrings.xml", "<sst " + ns + "><si><t>이름</t></si><si><r><t>홍</t></r><r><t>길동</t></r>"
                                 "<rPh><t>ホン</t></rPh></si></sst>"},
        {"xl/worksheets/sheet1.xml",
         "<worksheet " + ns + R"(><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1"><v>42</v></c></row>)"
                              R"(<row r="2" hidden="1"><c r="A2" t="inlineStr"><is><t>숨긴 행</t></is></c></row>)"
                              R"(<row r="3"><c r="A3" t="s"><v>1</v></c><c r="B3" t="inlineStr"><is><t>직접</t></is></c></row>)"
                              "</sheetData></worksheet>"},
        {"xl/worksheets/sheet2.xml", "<worksheet " + ns + R"(><sheetData><row r="1"><c t="inlineStr"><is><t>비밀</t></is></c></row></sheetData></worksheet>)"},
    }));
    ASSERT_TRUE(doc);
    EXPECT_EQ(doc->format, ex::DocumentFormat::Xlsx);
    ASSERT_EQ(doc->blocks.size(), 4U);
    EXPECT_EQ(doc->blocks[0], (ex::TextBlock{"보이는!1 cell1", "이름", 0, 1}));
    EXPECT_EQ(doc->blocks[1], (ex::TextBlock{"보이는!1 cell2", "42", 0, 2}));
    EXPECT_EQ(doc->blocks[2], (ex::TextBlock{"보이는!3 cell1", "홍길동", 0, 3}));
    EXPECT_EQ(doc->blocks[3], (ex::TextBlock{"보이는!3 cell2", "직접", 0, 4}));
    EXPECT_EQ(doc->omitted.hidden, 2U);  // 숨긴 시트 1, 숨긴 행 1
}

TEST(ExtractOffice, PptxSlidesInNumberOrderAndHiddenSlides) {
    const auto slide = [](std::string text, bool hidden = false) {
        return std::string(R"(<p:sld xmlns:p="p" xmlns:a="a")") + (hidden ? R"( show="0")" : "") +
               "><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>" + text +
               "</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>";
    };
    const auto doc = run(make_zip({{"ppt/presentation.xml", "<p:presentation xmlns:p=\"p\"/>"},
                                   {"ppt/slides/slide10.xml", slide("열")},
                                   {"ppt/slides/slide2.xml", slide("둘")},
                                   {"ppt/slides/slide3.xml", slide("숨김", true)},
                                   {"ppt/notesSlides/notesSlide2.xml", "<n/>"}}));
    ASSERT_TRUE(doc);
    EXPECT_EQ(texts(*doc), (std::vector<std::string>{"둘", "열"}));
    EXPECT_EQ(doc->blocks[1].where, "slide10");
    EXPECT_EQ(doc->omitted.hidden, 1U);
    EXPECT_EQ(doc->omitted.other_parts, 1U);
}

// 글상자와 수식(#234, 결정 #235): 글상자 앞 글을 잃지 않고, 옛 판용 대체 내용은 두 번 내지 않으며, 수식 스크립트를 낸다.
TEST(ExtractOffice, TextBoxesAndEquations) {
    const std::string box = R"(<w:txbxContent><w:p><w:r><w:t>상자 글</w:t></w:r></w:p></w:txbxContent>)";
    const auto docx_doc = run(docx(
        R"(<w:p><w:r><w:t>앞 글</w:t></w:r><w:r><mc:AlternateContent xmlns:mc="mc"><mc:Choice Requires="wps"><w:drawing>)"
        R"(<wps:txbx xmlns:wps="wps">)" + box + R"(</wps:txbx></w:drawing></mc:Choice><mc:Fallback><w:pict>)"
        R"(<v:textbox xmlns:v="v">)" + box + R"(</v:textbox></w:pict></mc:Fallback></mc:AlternateContent></w:r>)"
        R"(<w:r><w:t>뒤 글</w:t></w:r></w:p>)"));
    ASSERT_TRUE(docx_doc);
    EXPECT_EQ(texts(*docx_doc), (std::vector<std::string>{"앞 글", "상자 글", "뒤 글"}));

    const std::string section = R"(<hs:sec xmlns:hs="hs" xmlns:hp="hp"><hp:p><hp:run><hp:t>식</hp:t></hp:run>)"
                                R"(<hp:run><hp:equation><hp:script>{a} over {b}</hp:script></hp:equation></hp:run>)"
                                R"(<hp:run><hp:t>끝</hp:t></hp:run></hp:p></hs:sec>)";
    const auto hwpx_doc = run(make_zip({{"mimetype", "application/hwp+zip", true}, {"Contents/section0.xml", section}}));
    ASSERT_TRUE(hwpx_doc);
    EXPECT_EQ(texts(*hwpx_doc), std::vector<std::string>{"식 {a} over {b} 끝"});
}

// 넣은 파일(결정 #238): docx 안 docx, OLE 로 싼 docx 는 뽑고, 옛 형식 OLE 는 세기만 하며, 그림은 풀지 않는다.
TEST(ExtractOffice, EmbeddedFiles) {
    using pa_test::hwp::make_cfb;
    using pa_test::hwp::none;
    const auto inner = docx("<w:p><w:r><w:t>넣은 문서 글</w:t></w:r></w:p>");
    const auto packaged = make_cfb({{u"Root Entry", 5, "", none, none, 1}, {u"Package", 2, inner}});
    const auto legacy = make_cfb({{u"Root Entry", 5, "", none, none, 1}, {u"Workbook", 2, std::string(600, 'x')}});
    const auto doc = run(docx("<w:p><w:r><w:t>바깥 글</w:t></w:r></w:p>",
                              {{"word/embeddings/inner.docx", inner},
                               {"word/embeddings/oleObject1.bin", packaged},
                               {"word/embeddings/oleObject2.bin", legacy},
                               {"word/media/image1.png", std::string(100, '\x89')}}));
    ASSERT_TRUE(doc) << ex::error_name(doc.error());
    EXPECT_EQ(texts(*doc), (std::vector<std::string>{"바깥 글", "넣은 문서 글", "넣은 문서 글"}));
    EXPECT_EQ(doc->blocks[1].where, "word/embeddings/inner.docx:p1");
    EXPECT_EQ(doc->omitted.other_parts, 2U);  // 옛 형식 개체와 읽지 않은 미디어 부품
}

TEST(ExtractOffice, HwpxSectionsMemoAndEncryption) {
    const std::string section = R"(<hs:sec xmlns:hs="hs" xmlns:hp="hp"><hp:p><hp:run><hp:t>첫 문단</hp:t></hp:run></hp:p>)"
                                R"(<hp:p><hp:run><hp:t>표 앞</hp:t></hp:run><hp:run><hp:tbl><hp:tr><hp:tc><hp:subList>)"
                                R"(<hp:p><hp:run><hp:t>칸 글</hp:t></hp:run></hp:p></hp:subList></hp:tc></hp:tr></hp:tbl></hp:run></hp:p>)"
                                R"(<hp:p><hp:run><hp:t>본문<hp:memo><hp:t>메모 글</hp:t></hp:memo></hp:t></hp:run></hp:p></hs:sec>)";
    const auto doc = run(make_zip({{"mimetype", "application/hwp+zip", true},
                                   {"Contents/section1.xml", section},
                                   {"Contents/section0.xml", R"(<hs:sec xmlns:hs="hs" xmlns:hp="hp"><hp:p><hp:t>영</hp:t></hp:p></hs:sec>)"},
                                   {"Preview/PrvText.txt", "미리보기"}}));
    ASSERT_TRUE(doc);
    EXPECT_EQ(doc->format, ex::DocumentFormat::Hwpx);
    EXPECT_EQ(texts(*doc), (std::vector<std::string>{"영", "첫 문단", "표 앞", "칸 글", "본문"}));
    EXPECT_EQ(doc->blocks[0].where, "section0 p1");
    EXPECT_EQ(doc->omitted.comments, 1U);
    EXPECT_EQ(doc->omitted.other_parts, 1U);
    const auto locked = run(make_zip({{"mimetype", "application/hwp+zip", true},
                                      {"META-INF/manifest.xml", "<odf:manifest><odf:file-entry><odf:encryption-data/></odf:file-entry></odf:manifest>"},
                                      {"Contents/section0.xml", "<x/>"}}));
    EXPECT_EQ(locked.error(), ex::ExtractError::Encrypted);
}

TEST(ExtractZip, NestedDocumentsNamesAndDepth) {
    const auto inner = docx("<w:p><w:r><w:t>안쪽</w:t></w:r></w:p>");
    // 이름이 CP949 인 항목(UTF-8 표시 없음)도 위치에 한글로 남는다.
    const auto outer = run(make_zip({{"보고서.docx", inner}, {"\xB0\xA1.txt", "글"}, {"그림.png", "x"}}));
    ASSERT_TRUE(outer);
    EXPECT_EQ(outer->format, ex::DocumentFormat::Zip);
    EXPECT_EQ(outer->blocks[0].where, "보고서.docx:p1");
    EXPECT_EQ(outer->blocks[1].where, "가.txt:line1");
    EXPECT_EQ(outer->omitted.other_parts, 1U);
    // 깊이 2: zip 안 zip 안 문서는 거절(풀 수 있는 끝은 zip 안 문서).
    const auto deep = run(make_zip({{"a.zip", make_zip({{"b.zip", make_zip({{"c.txt", "글"}})}})}}));
    EXPECT_EQ(deep.error(), ex::ExtractError::Bomb);
    // 안의 문서 하나라도 못 읽으면 전체를 거절한다.
    EXPECT_EQ(run(make_zip({{"ok.txt", "글"}, {"old.doc", "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"}})).error(),
              ex::ExtractError::Damaged);
}

TEST(ExtractLimits, BombsAndLimits) {
    // 압축률 폭탄: 같은 글자 1 MiB 를 deflate 하면 압축률이 100 을 크게 넘는다.
    EXPECT_EQ(run(make_zip({{"a.txt", std::string(1 << 20, 'a')}})).error(), ex::ExtractError::Bomb);
    ex::ExtractLimits small;
    small.zip_entries = 2;
    EXPECT_EQ(run(make_zip({{"a.txt", "1"}, {"b.txt", "2"}, {"c.txt", "3"}}), {}, small).error(), ex::ExtractError::Bomb);
    small = {};
    small.total_bytes = 10;
    EXPECT_EQ(run(make_zip({{"a.txt", "0123456789", true}, {"b.txt", "0", true}}), {}, small).error(), ex::ExtractError::Bomb);
    small = {};
    small.output_bytes = 4;
    EXPECT_EQ(run("abcdef", {}, small).error(), ex::ExtractError::TooLarge);
    small = {};
    small.file_bytes = 3;
    EXPECT_EQ(run("abcd", {}, small).error(), ex::ExtractError::TooLarge);
    small = {};
    small.nested_documents = 1;
    EXPECT_EQ(run(make_zip({{"a.txt", "1"}, {"b.txt", "2"}}), {}, small).error(), ex::ExtractError::Bomb);
}

TEST(ExtractLimits, HostileXmlAndBrokenFiles) {
    // DOCTYPE·개체 선언(XXE, 개체 확장)은 해석하지 않는다.
    EXPECT_EQ(run(docx("")).error(), ex::ExtractError::NoText);  // 빈 본문은 글자 없음
    const auto xxe = make_zip({{"word/document.xml", R"(<?xml version="1.0"?><!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><d>&e;</d>)"}});
    EXPECT_EQ(run(xxe).error(), ex::ExtractError::Damaged);
    std::string deep;
    for (int i = 0; i < 300; ++i) {
        deep += "<w:p>";
    }
    EXPECT_EQ(run(docx(deep)).error(), ex::ExtractError::Bomb);
    // 잘린 zip
    const auto whole = docx("<w:p><w:r><w:t>글</w:t></w:r></w:p>");
    EXPECT_FALSE(run(whole.substr(0, whole.size() / 2)));
    // CFB 머리만 있고 몸이 없는 파일. 옛 형식·hwp 판정은 extract_hwp_test 가 진짜 CFB 로 본다.
    EXPECT_EQ(run(std::string("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8)).error(), ex::ExtractError::Damaged);
    EXPECT_EQ(run(std::string("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8), "hwp").error(), ex::ExtractError::Damaged);
}

TEST(ExtractProtocol, RoundTripAndRejectsBadOutput) {
    ex::ExtractedDocument doc{ex::DocumentFormat::Hwpx, {{"section0 p1", "가"}}, {1, 2, 3, 4}};
    const auto back = ex::from_json(ex::to_json(doc));
    ASSERT_TRUE(back && *back);
    EXPECT_EQ((*back)->blocks, doc.blocks);
    EXPECT_EQ((*back)->omitted, doc.omitted);
    const auto failed = ex::from_json(ex::to_json(std::unexpected(ex::ExtractError::Encrypted)));
    ASSERT_TRUE(failed);
    EXPECT_EQ(failed->error(), ex::ExtractError::Encrypted);
    for (const std::string_view bad : {"", "{", "[]", R"({"v":2,"ok":true})", R"({"v":1,"ok":false,"error":"x"})",
                                       R"({"v":1,"ok":true,"format":"exe","blocks":[],"omitted":{}})",
                                       R"({"v":1,"ok":true,"format":"txt","blocks":[{"at":1}],"omitted":{}})"}) {
        EXPECT_EQ(ex::from_json(bad).error(), ex::RunError::BadOutput) << bad;
    }
}

TEST(ExtractText, XmlIsNeverSentAsMarkup) {
    // 한글 XML(HWPML): 문단 글자만, 숨은 설명은 빼고 센다. 확장자가 hwp 여도 내용으로 판별한다.
    const auto hwpml = run(R"(<?xml version="1.0" encoding="utf-8"?><HWPML Version="2.1"><BODY><SECTION>)"
                           R"(<P><TEXT><CHAR>첫 문단</CHAR></TEXT></P><P><TEXT><CHAR>둘<TAB/>째</CHAR>)"
                           R"(<HIDDENCOMMENT><P><TEXT><CHAR>숨은 설명</CHAR></TEXT></P></HIDDENCOMMENT></TEXT></P>)"
                           R"(</SECTION></BODY></HWPML>)",
                           "hwp");
    ASSERT_TRUE(hwpml);
    EXPECT_EQ(hwpml->format, ex::DocumentFormat::Hwpml);
    EXPECT_EQ(texts(*hwpml), (std::vector<std::string>{"첫 문단", "둘\t째"}));
    EXPECT_EQ(hwpml->omitted.comments, 1U);
    // HWPML 은 짧은 글자 값의 내부 개체(nbsp)만 받는다. 외부 DTD, 다른 개체를 부르는 개체(개체 확장 공격)는 거절.
    const auto doc = [](std::string dtd) {
        return R"(<?xml version="1.0"?><!DOCTYPE HWPML )" + dtd +
               R"(><HWPML><BODY><SECTION><P><TEXT><CHAR>가&nbsp;나</CHAR></TEXT></P></SECTION></BODY></HWPML>)";
    };
    const auto nbsp = run(doc(R"([<!ENTITY nbsp "&#160;">])"));
    ASSERT_TRUE(nbsp);
    EXPECT_EQ(texts(*nbsp), std::vector<std::string>{"\xEA\xB0\x80\xC2\xA0\xEB\x82\x98"});  // 가 U+00A0 나
    EXPECT_EQ(run(doc(R"(SYSTEM "http://example.invalid/x.dtd")")).error(), ex::ExtractError::Damaged);
    EXPECT_EQ(run(doc(R"([<!ENTITY a "aaaaaaaaaa"><!ENTITY nbsp "&a;&a;&a;&a;">])")).error(), ex::ExtractError::Damaged);
    EXPECT_EQ(run(doc(R"([<!ENTITY nbsp SYSTEM "file:///etc/passwd">])")).error(), ex::ExtractError::Damaged);
    // 다른 XML 은 마크업째 보내지 않고 거절한다.
    EXPECT_EQ(run("<?xml version=\"1.0\"?><data><secret>값</secret></data>", "txt").error(),
              ex::ExtractError::Unsupported);
}
