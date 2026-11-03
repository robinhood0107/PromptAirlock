#pragma once

// 시험·fuzz 용 hwp 5.0 작성기. 바이너리 시험 파일을 저장소에 두지 않고(공개 감사는 NUL 이 든 파일을 받지 않음)
// 시험 안에서 CFB 를 만든다. 섹터 512 byte, FAT 섹터 1개, 디렉터리 섹터 1개(항목 4개까지).
// 작은 스트림 문턱을 0 으로 둬 모든 스트림이 일반 섹터를 쓴다(작은 스트림 경로는 받은 문서 측정과 fuzz 가 본다).
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace pa_test::hwp {

inline constexpr std::uint32_t endc = 0xFFFFFFFE;
inline constexpr std::uint32_t none = 0xFFFFFFFF;

inline void put32(std::string& b, std::size_t at, std::uint32_t v) { std::memcpy(b.data() + at, &v, 4); }
inline void put16(std::string& b, std::size_t at, std::uint16_t v) { std::memcpy(b.data() + at, &v, 2); }

struct Node {
    std::u16string name;
    std::uint8_t type;  // 1 저장소, 2 스트림
    std::string data;
    std::uint32_t left = none, right = none, child = none;
};

// nodes[0] 은 뿌리.
inline std::string make_cfb(std::vector<Node> nodes) {
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
    for (std::size_t i = 0; i < fat.size() && i < 128; ++i) {
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

inline std::string file_header(std::uint32_t props, std::uint32_t version = 0x05000300) {
    std::string h(256, '\0');
    std::memcpy(h.data(), "HWP Document File", 17);
    put32(h, 32, version);
    put32(h, 36, props);
    return h;
}

inline std::string record(std::uint32_t tag, std::uint32_t level, const std::string& data) {
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

// FileHeader 와 BodyText/Section0 하나짜리 hwp.
inline std::string hwp(std::uint32_t props, const std::string& section, std::uint32_t version = 0x05000300) {
    return make_cfb({{u"Root Entry", 5, "", none, none, 1},
                     {u"FileHeader", 2, file_header(props, version), none, 2},
                     {u"BodyText", 1, "", none, none, 3},
                     {u"Section0", 2, section}});
}

}  // namespace pa_test::hwp
