// hwp 5.0 과 CFB(ADR 0028): 문단 글자, 조판 제어 문자, 머리글·숨은 설명 건너뛰기, 압축, 잠긴 문서, 옛 형식, 깨진 CFB.
// CFB 는 시험 안에서 만든다(바이너리 시험 파일을 저장소에 두지 않음). 작은 스트림 문턱을 0 으로 둬 모든 스트림이
// 일반 섹터를 쓰게 한다(작은 스트림 경로는 받은 문서 측정과 fuzz 가 본다).
#include <gtest/gtest.h>
#include <zlib.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "prompt_airlock/extract/document.hpp"

namespace ex = prompt_airlock::extract;

namespace {

constexpr std::uint32_t endc = 0xFFFFFFFE;
constexpr std::uint32_t none = 0xFFFFFFFF;

void put32(std::string& b, std::size_t at, std::uint32_t v) { std::memcpy(b.data() + at, &v, 4); }
void put16(std::string& b, std::size_t at, std::uint16_t v) { std::memcpy(b.data() + at, &v, 2); }

struct Node {
    std::u16string name;
    std::uint8_t type;  // 1 저장소, 2 스트림
    std::string data;
    std::uint32_t left = none, right = none, child = none;
};

// 섹터 512 byte, FAT 섹터 1개, 디렉터리 섹터 1개(항목 4개까지). nodes[0] 은 뿌리.
std::string make_cfb(std::vector<Node> nodes) {
    std::string out(512, '\0');
    std::memcpy(out.data(), "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8);
    put16(out, 0x18, 0x3E);
    put16(out, 0x1A, 3);
    put16(out, 0x1C, 0xFFFE);
    put16(out, 0x1E, 9);
    put16(out, 0x20, 6);
    put32(out, 0x2C, 1);     // FAT 섹터 수
    put32(out, 0x30, 1);     // 디렉터리 첫 섹터
    put32(out, 0x38, 0);     // 작은 스트림 문턱
    put32(out, 0x3C, endc);  // 작은 FAT 없음
    put32(out, 0x44, endc);
    put32(out, 0x4C, 0);  // FAT 은 섹터 0
    for (std::size_t i = 1; i < 109; ++i) {
        put32(out, 0x4C + i * 4, none);
    }
    std::vector<std::uint32_t> fat = {0xFFFFFFFD, endc};
    std::string data;
    std::vector<std::uint32_t> starts(nodes.size(), endc);
    for (std::size_t i = 1; i < nodes.size(); ++i) {
        if (nodes[i].type != 2 || nodes[i].data.empty()) {
            continue;
        }
        const auto sectors = (nodes[i].data.size() + 511) / 512;
        starts[i] = static_cast<std::uint32_t>(fat.size());
        for (std::size_t k = 0; k < sectors; ++k) {
            fat.push_back(k + 1 < sectors ? static_cast<std::uint32_t>(fat.size() + 1) : endc);
        }
        std::string padded = nodes[i].data;
        padded.resize(sectors * 512, '\0');
        data += padded;
    }
    std::string fat_sector(512, '\xFF');
    for (std::size_t i = 0; i < fat.size(); ++i) {
        put32(fat_sector, i * 4, fat[i]);
    }
    std::string dir(512, '\0');
    for (std::size_t i = 0; i < 4; ++i) {
        put32(dir, i * 128 + 0x44, none);
        put32(dir, i * 128 + 0x48, none);
        put32(dir, i * 128 + 0x4C, none);
    }
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        const auto at = i * 128;
        for (std::size_t k = 0; k < nodes[i].name.size(); ++k) {
            put16(dir, at + k * 2, nodes[i].name[k]);
        }
        put16(dir, at + 0x40, static_cast<std::uint16_t>((nodes[i].name.size() + 1) * 2));
        dir[at + 0x42] = static_cast<char>(i == 0 ? 5 : nodes[i].type);
        put32(dir, at + 0x44, nodes[i].left);
        put32(dir, at + 0x48, nodes[i].right);
        put32(dir, at + 0x4C, nodes[i].child);
        put32(dir, at + 0x74, starts[i]);
        put32(dir, at + 0x78, static_cast<std::uint32_t>(nodes[i].data.size()));
    }
    return out + fat_sector + dir + data;
}

std::string file_header(std::uint32_t props, std::uint32_t version = 0x05000300) {
    std::string h(256, '\0');
    std::memcpy(h.data(), "HWP Document File", 17);
    put32(h, 32, version);
    put32(h, 36, props);
    return h;
}

std::string record(std::uint32_t tag, std::uint32_t level, const std::string& data) {
    std::string r(4, '\0');
    if (data.size() < 0xFFF) {
        put32(r, 0, tag | level << 10 | static_cast<std::uint32_t>(data.size()) << 20);
    } else {
        put32(r, 0, tag | level << 10 | 0xFFFU << 20);
        r.resize(8);
        put32(r, 4, static_cast<std::uint32_t>(data.size()));
    }
    return r + data;
}

std::string utf16(const std::u16string& s) {
    std::string out(s.size() * 2, '\0');
    std::memcpy(out.data(), s.data(), out.size());
    return out;
}

constexpr std::uint32_t para_header = 0x10 + 50;
constexpr std::uint32_t para_text = 0x10 + 51;
constexpr std::uint32_t ctrl_header = 0x10 + 55;

std::string ctrl(const char (&id)[5]) {  // 4 글자 id 를 저장 순서(거꾸로)로
    return std::string{id[3], id[2], id[1], id[0]} + std::string(8, '\0');
}

std::string hwp(std::uint32_t props, const std::string& section, std::uint32_t version = 0x05000300) {
    return make_cfb({{u"Root Entry", 5, "", none, none, 1},
                     {u"FileHeader", 2, file_header(props, version), none, 2},
                     {u"BodyText", 1, "", none, none, 3},
                     {u"Section0", 2, section}});
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
