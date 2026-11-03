// hwp 5.0 과 CFB(ADR 0028): 문단 글자, 조판 제어 문자, 머리글·숨은 설명 건너뛰기, 압축, 잠긴 문서, 옛 형식, 깨진 CFB.
// CFB 는 시험 안에서 만든다(tests/support/hwp_writer.hpp).
#include <gtest/gtest.h>
#include <zlib.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "hwp_writer.hpp"
#include "prompt_airlock/extract/document.hpp"

namespace ex = prompt_airlock::extract;

namespace {

using pa_test::hwp::hwp;
using pa_test::hwp::make_cfb;
using pa_test::hwp::none;
using pa_test::hwp::put32;
using pa_test::hwp::record;

std::string utf16(const std::u16string& s) {
    std::string out(s.size() * 2, '\0');
    std::memcpy(out.data(), s.data(), out.size());
    return out;
}

constexpr std::uint32_t para_header = 0x10 + 50;
constexpr std::uint32_t para_text = 0x10 + 51;
constexpr std::uint32_t ctrl_header = 0x10 + 55;
constexpr std::uint32_t eqedit = 0x10 + 72;

std::string equation(const std::u16string& script) {  // 속성 4 byte + 길이 2 byte + 스크립트
    return std::string(4, '\0') + std::string{static_cast<char>(script.size()), 0} + utf16(script);
}

std::string ctrl(const char (&id)[5]) {  // 4 글자 id 를 저장 순서(거꾸로)로
    return std::string{id[3], id[2], id[1], id[0]} + std::string(8, '\0');
}

std::string deflate_raw(const std::string& in) {
    z_stream z{};
    deflateInit2(&z, Z_BEST_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    std::string out(compressBound(static_cast<uLong>(in.size())) + 16, '\0');
    z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    z.avail_in = static_cast<uInt>(in.size());
    z.next_out = reinterpret_cast<Bytef*>(out.data());
    z.avail_out = static_cast<uInt>(out.size());
    deflate(&z, Z_FINISH);
    out.resize(z.total_out);
    deflateEnd(&z);
    return out;
}

auto run(const std::string& bytes) { return ex::extract(std::as_bytes(std::span(bytes.data(), bytes.size())), "hwp"); }

std::vector<std::string> texts(const ex::ExtractedDocument& doc) {
    std::vector<std::string> out;
    for (const auto& b : doc.blocks) {
        out.push_back(b.text);
    }
    return out;
}

// 확장 제어 문자(표 = 11)는 8 단위, 탭(9)도 8 단위, 줄 바꿈(10)은 1 단위.
const std::u16string extended_table = std::u16string(1, 11) + u"tbl " + std::u16string(2, 0) + std::u16string(1, 11);
const std::u16string tab = std::u16string(1, 9) + std::u16string(6, 0) + std::u16string(1, 9);

}  // namespace

TEST(ExtractHwp, ParagraphsAndControlCharacters) {
    const auto section = record(para_header, 0, std::string(22, '\0')) +
                         record(para_text, 1, utf16(u"첫 문단" + tab + u"탭" + extended_table + u"끝\r")) +
                         record(para_header, 0, std::string(22, '\0')) +
                         record(para_text, 1, utf16(std::u16string(u"줄") + char16_t{10} + u"바꿈 😀\r"));
    const auto doc = run(hwp(0, section));
    ASSERT_TRUE(doc) << ex::error_name(doc.error());
    EXPECT_EQ(doc->format, ex::DocumentFormat::Hwp);
    EXPECT_EQ(texts(*doc), (std::vector<std::string>{"첫 문단\t탭끝", "줄 바꿈 😀"}));
    EXPECT_EQ(doc->blocks[0].where, "section0 p1");
}

TEST(ExtractHwp, HeadersFootersAndHiddenCommentsAreSkipped) {
    const auto section = record(para_text, 0, utf16(u"본문")) + record(ctrl_header, 1, ctrl("head")) +
                         record(para_text, 2, utf16(u"머리글")) + record(ctrl_header, 1, ctrl("tcmt")) +
                         record(para_text, 2, utf16(u"숨은 설명")) + record(para_text, 1, utf16(u"다시 본문"));
    const auto doc = run(hwp(0, section));
    ASSERT_TRUE(doc);
    EXPECT_EQ(texts(*doc), (std::vector<std::string>{"본문", "다시 본문"}));
    EXPECT_EQ(doc->omitted.other_parts, 1U);
    EXPECT_EQ(doc->omitted.comments, 1U);
}

// 수식(결정 #235): 스크립트를 글자로 낸다. 머리글 안 수식은 머리글과 함께 건너뛴다. 길이가 레코드를 넘으면 손상.
TEST(ExtractHwp, EquationScripts) {
    const auto section = record(para_text, 0, utf16(u"식\r")) + record(ctrl_header, 1, ctrl("eqed")) +
                         record(eqedit, 2, equation(u"{900101 - 1234567} over 2")) +
                         record(ctrl_header, 1, ctrl("head")) + record(eqedit, 2, equation(u"머리글 식"));
    const auto doc = run(hwp(0, section));
    ASSERT_TRUE(doc) << ex::error_name(doc.error());
    EXPECT_EQ(texts(*doc), (std::vector<std::string>{"식", "{900101 - 1234567} over 2"}));
    EXPECT_EQ(doc->blocks[1].where, "section0 eq1");
    EXPECT_EQ(run(hwp(0, record(eqedit, 0, equation(u"x").substr(0, 7)))).error(), ex::ExtractError::Damaged);
}

TEST(ExtractHwp, CompressedSectionsAndLongRecords) {
    std::u16string long_text;  // 크기 칸 0xFFF 를 넘는 레코드, 압축률 상한에 걸리지 않게 섞인 글자
    for (std::size_t i = 0; i < 3000; ++i) {
        long_text.push_back(static_cast<char16_t>(0xAC00 + (i * 7919) % 11172));
    }
    const auto doc = run(hwp(1, deflate_raw(record(para_text, 0, utf16(long_text)))));
    ASSERT_TRUE(doc) << ex::error_name(doc.error());
    EXPECT_EQ(doc->blocks.at(0).text.size(), 3000U * 3);
    // 압축률 폭탄
    EXPECT_EQ(run(hwp(1, deflate_raw(record(para_text, 0, std::string(4 << 20, 'a'))))).error(),
              ex::ExtractError::Bomb);
    // 잘린 압축
    const auto packed = deflate_raw(record(para_text, 0, utf16(u"글")));
    EXPECT_EQ(run(hwp(1, packed.substr(0, packed.size() / 2))).error(), ex::ExtractError::Damaged);
}

TEST(ExtractHwp, LockedOldAndBrokenFiles) {
    const auto section = record(para_text, 0, utf16(u"글"));
    for (const std::uint32_t bit : {1U << 1, 1U << 2, 1U << 4, 1U << 8, 1U << 10}) {  // 암호, 배포용, DRM, 인증서
        EXPECT_EQ(run(hwp(bit, section)).error(), ex::ExtractError::Encrypted) << bit;
    }
    EXPECT_EQ(run(hwp(0, section, 0x03000000)).error(), ex::ExtractError::Unsupported);
    // FileHeader 가 없는 CFB 는 doc·xls·ppt 같은 옛 형식
    EXPECT_EQ(run(make_cfb({{u"Root Entry", 5, "", none, none, 1}, {u"WordDocument", 2, std::string(600, 'x')}})).error(),
              ex::ExtractError::LegacyFormat);
    // 레코드 크기가 남은 byte 보다 큼
    EXPECT_EQ(run(hwp(0, record(para_text, 0, utf16(u"글")).substr(0, 5))).error(), ex::ExtractError::Damaged);
    // FAT 사슬 순환: 스트림이 자기 섹터를 가리킴
    auto cyclic = hwp(0, std::string(1200, 'x'));
    put32(cyclic, 512 + 3 * 4, 3);
    EXPECT_EQ(run(cyclic).error(), ex::ExtractError::Damaged);
    // 잘린 파일
    const auto whole = hwp(0, section);
    EXPECT_EQ(run(whole.substr(0, 700)).error(), ex::ExtractError::Damaged);
}
