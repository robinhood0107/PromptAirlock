// 복합 문서(CFB, MS-CFB) 읽기. hwp 5.0 이 쓰는 컨테이너다. 섹터 사슬은 순환·범위를 검사하며 따라가고,
// 디렉터리 나무는 방문 표시로 순환을 막는다. 쓰기와 수정은 하지 않는다.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>

#include "detail.hpp"

namespace prompt_airlock::extract::detail {
namespace {

constexpr std::uint32_t end_of_chain = 0xFFFFFFFE;
constexpr std::uint32_t free_sector = 0xFFFFFFFF;
constexpr std::uint32_t no_stream = 0xFFFFFFFF;
constexpr std::size_t header_bytes = 512;
constexpr std::size_t dir_entry_bytes = 128;
constexpr std::size_t unbounded = std::numeric_limits<std::size_t>::max() / 2;  // 크기를 모르는 사슬(디렉터리)

[[nodiscard]] std::uint32_t u32(std::span<const std::byte> b, std::size_t at) {
    std::uint32_t v = 0;
    std::memcpy(&v, b.data() + at, 4);  // CFB 는 little-endian, 지원 플랫폼도 little-endian
    return v;
}
[[nodiscard]] std::uint16_t u16(std::span<const std::byte> b, std::size_t at) {
    std::uint16_t v = 0;
    std::memcpy(&v, b.data() + at, 2);
    return v;
}

}  // namespace

std::expected<Cfb, ExtractError> Cfb::open(std::span<const std::byte> file, Context& context) {
    if (file.size() < header_bytes ||
        std::memcmp(file.data(), "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8) != 0) {
        return std::unexpected(ExtractError::Damaged);
    }
    Cfb cfb;
    cfb.file_ = file;
    const auto sector_shift = u16(file, 0x1E);
    const auto mini_shift = u16(file, 0x20);
    if ((sector_shift != 9 && sector_shift != 12) || mini_shift != 6 || u16(file, 0x1C) != 0xFFFE) {
        return std::unexpected(ExtractError::Damaged);
    }
    cfb.sector_ = std::size_t{1} << sector_shift;
    cfb.mini_cutoff_ = u32(file, 0x38);
    const auto fat_sectors = u32(file, 0x2C);
    const auto first_dir = u32(file, 0x30);
    const auto first_mini_fat = u32(file, 0x3C);
    const auto mini_fat_sectors = u32(file, 0x40);
    auto difat_next = u32(file, 0x44);
    const auto difat_sectors = u32(file, 0x48);
    const std::size_t total_sectors = (file.size() - header_bytes + cfb.sector_ - 1) / cfb.sector_;
    if (fat_sectors > total_sectors || difat_sectors > total_sectors || mini_fat_sectors > total_sectors) {
        return std::unexpected(ExtractError::Damaged);
    }
    // DIFAT: 헤더의 109개 + DIFAT 섹터 사슬.
    std::vector<std::uint32_t> fat_list;
    for (std::size_t i = 0; i < 109 && fat_list.size() < fat_sectors; ++i) {
        fat_list.push_back(u32(file, 0x4C + i * 4));
    }
    for (std::uint32_t n = 0; fat_list.size() < fat_sectors; ++n) {
        if (n >= difat_sectors || difat_next >= total_sectors) {
            return std::unexpected(ExtractError::Damaged);
        }
        const auto at = header_bytes + static_cast<std::size_t>(difat_next) * cfb.sector_;
        const auto per = cfb.sector_ / 4 - 1;
        for (std::size_t i = 0; i < per && fat_list.size() < fat_sectors; ++i) {
            fat_list.push_back(u32(file, at + i * 4));
        }
        difat_next = u32(file, at + per * 4);
    }
    for (const auto s : fat_list) {
        if (s >= total_sectors) {
            return std::unexpected(ExtractError::Damaged);
        }
        const auto at = header_bytes + static_cast<std::size_t>(s) * cfb.sector_;
        if (at + cfb.sector_ > file.size()) {
            return std::unexpected(ExtractError::Damaged);
        }
        for (std::size_t i = 0; i < cfb.sector_ / 4; ++i) {
            cfb.fat_.push_back(u32(file, at + i * 4));
        }
    }
    // 디렉터리와 작은 FAT 는 보통 섹터 사슬이다.
    auto dir = cfb.chain(first_dir, unbounded, false, context);
    if (!dir) {
        return std::unexpected(dir.error());
    }
    for (std::size_t at = 0; at + dir_entry_bytes <= dir->size(); at += dir_entry_bytes) {
        const auto e = std::as_bytes(std::span(*dir)).subspan(at, dir_entry_bytes);
        Entry entry;
        const auto name_bytes = std::min<std::size_t>(u16(e, 0x40), 64);
        for (std::size_t k = 0; k + 1 < name_bytes; k += 2) {
            const auto c = u16(e, k);
            if (c == 0) {
                break;
            }
            entry.name.push_back(c);
        }
        entry.type = static_cast<std::uint8_t>(e[0x42]);
        entry.left = u32(e, 0x44);
        entry.right = u32(e, 0x48);
        entry.child = u32(e, 0x4C);
        entry.start = u32(e, 0x74);
        entry.size = u32(e, 0x78);  // 버전 3 은 아래 4 byte 만 쓴다. 32 bit 를 넘는 스트림은 받지 않는다.
        if (u32(e, 0x7C) != 0 && sector_shift == 12) {
            return std::unexpected(ExtractError::TooLarge);
        }
        cfb.entries_.push_back(std::move(entry));
    }
    if (cfb.entries_.empty() || cfb.entries_[0].type != 5) {
        return std::unexpected(ExtractError::Damaged);
    }
    if (mini_fat_sectors > 0) {
        auto mini_fat = cfb.chain(first_mini_fat, std::size_t{mini_fat_sectors} * cfb.sector_, false, context);
        if (!mini_fat) {
            return std::unexpected(mini_fat.error());
        }
        for (std::size_t at = 0; at + 4 <= mini_fat->size(); at += 4) {
            cfb.mini_fat_.push_back(u32(std::as_bytes(std::span(*mini_fat)), at));
        }
        auto mini = cfb.chain(cfb.entries_[0].start, cfb.entries_[0].size, false, context);
        if (!mini) {
            return std::unexpected(mini.error());
        }
        cfb.mini_stream_ = std::move(*mini);
    }
    return cfb;
}

std::expected<std::string, ExtractError> Cfb::chain(std::uint32_t start, std::size_t size, bool mini,
                                                    Context& context) const {
    const auto& table = mini ? mini_fat_ : fat_;
    const std::size_t unit = mini ? 64 : sector_;
    const std::size_t limit = std::min(size, context.limits.entry_bytes + 1);
    std::string out;
    std::size_t steps = 0;
    for (auto s = start; s != end_of_chain && out.size() < limit;) {
        if (s == free_sector || s >= table.size() || ++steps > table.size()) {
            return std::unexpected(ExtractError::Damaged);  // 범위 밖 또는 순환
        }
        if (mini) {
            const auto at = static_cast<std::size_t>(s) * unit;
            if (at + unit > mini_stream_.size()) {
                return std::unexpected(ExtractError::Damaged);
            }
            out.append(mini_stream_, at, unit);
        } else {
            const auto at = header_bytes + static_cast<std::size_t>(s) * unit;
            if (at >= file_.size()) {
                return std::unexpected(ExtractError::Damaged);
            }
            const auto n = std::min(unit, file_.size() - at);
            out.append(reinterpret_cast<const char*>(file_.data() + at), n);
        }
        s = table[s];
    }
    if (size != (unbounded)) {
        if (out.size() < size) {
            return std::unexpected(ExtractError::Damaged);  // 적힌 크기보다 짧은 사슬
        }
        out.resize(size);
    }
    return out;
}

std::expected<std::string, ExtractError> Cfb::read(std::string_view path, Context& context) const {
    // 경로는 "BodyText/Section0" 처럼 '/' 로 나눈다. 이름 비교는 ASCII 대소문자 무시(CFB 규칙).
    std::uint32_t storage = 0;
    std::size_t start = 0;
    while (true) {
        const auto slash = path.find('/', start);
        const auto part = path.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
        const auto found = find_child(storage, part);
        if (!found) {
            return std::unexpected(ExtractError::Damaged);
        }
        if (slash == std::string_view::npos) {
            const auto& e = entries_[*found];
            if (e.type != 2) {
                return std::unexpected(ExtractError::Damaged);
            }
            if (e.size > context.limits.entry_bytes || context.unpacked + e.size > context.limits.total_bytes) {
                return std::unexpected(ExtractError::Bomb);
            }
            auto data = chain(e.start, e.size, e.size < mini_cutoff_, context);
            if (data) {
                context.unpacked += data->size();
            }
            return data;
        }
        storage = *found;
        start = slash + 1;
    }
}

bool Cfb::contains(std::string_view path) const {
    std::uint32_t storage = 0;
    std::size_t start = 0;
    while (true) {
        const auto slash = path.find('/', start);
        const auto part = path.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
        const auto found = find_child(storage, part);
        if (!found) {
            return false;
        }
        if (slash == std::string_view::npos) {
            return true;
        }
        storage = *found;
        start = slash + 1;
    }
}

std::optional<std::uint32_t> Cfb::find_child(std::uint32_t storage, std::string_view name) const {
    if (storage >= entries_.size()) {
        return std::nullopt;
    }
    // 자식 나무(왼쪽·오른쪽 형제)를 돌며 이름이 같은 것을 찾는다. 방문 표시로 순환을 막는다.
    std::vector<bool> seen(entries_.size(), false);
    std::vector<std::uint32_t> todo{entries_[storage].child};
    while (!todo.empty()) {
        const auto id = todo.back();
        todo.pop_back();
        if (id == no_stream || id >= entries_.size() || seen[id]) {
            continue;
        }
        seen[id] = true;
        const auto& e = entries_[id];
        if (e.name.size() == name.size() &&
            std::ranges::equal(e.name, name, [](char16_t a, char b) {
                const auto lower = [](char32_t c) { return c >= U'A' && c <= U'Z' ? c + 32 : c; };
                return lower(a) == lower(static_cast<unsigned char>(b));
            })) {
            return id;
        }
        todo.push_back(e.left);
        todo.push_back(e.right);
    }
    return std::nullopt;
}

std::vector<std::string> Cfb::streams(std::string_view storage) const {
    std::vector<std::string> out;
    const auto parent = find_child(0, storage);
    if (!parent || entries_[*parent].type != 1) {
        return out;
    }
    std::vector<bool> seen(entries_.size(), false);
    std::vector<std::uint32_t> todo{entries_[*parent].child};
    while (!todo.empty()) {
        const auto id = todo.back();
        todo.pop_back();
        if (id == no_stream || id >= entries_.size() || seen[id]) {
            continue;
        }
        seen[id] = true;
        const auto& e = entries_[id];
        if (e.type == 2 && std::ranges::all_of(e.name, [](char16_t c) { return c > 0x20 && c < 0x7F; })) {
            auto& name = out.emplace_back();
            for (const char16_t c : e.name) {
                name.push_back(static_cast<char>(c));
            }
        }
        todo.push_back(e.left);
        todo.push_back(e.right);
    }
    std::ranges::sort(out, natural_less);
    return out;
}

}  // namespace prompt_airlock::extract::detail
