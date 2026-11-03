// 본 제품은 한컴의 HWP 문서 파일(.hwp) 공개 문서를 참고하여 개발하였습니다.
// hwp 5.0: CFB 안 FileHeader 의 속성으로 암호·배포용·DRM 을 거르고, BodyText/Section* 레코드에서 문단 글자를 뽑는다.
// 레코드 머리(32 bit) = 태그 10 bit, 단계 10 bit, 크기 12 bit(0xFFF 면 다음 32 bit 가 크기).
// 머리글·바닥글·각주·미주 안 문단은 본문이 아니므로 세기만 하고, 숨은 설명은 메모로 센다. 수식은 스크립트를 글자로 낸다.
#include <zlib.h>

#include <array>
#include <cstring>

#include "detail.hpp"

namespace prompt_airlock::extract::detail {
namespace {

constexpr std::uint32_t tag_para_text = 0x10 + 51;
constexpr std::uint32_t tag_ctrl_header = 0x10 + 55;
constexpr std::uint32_t tag_eqedit = 0x10 + 72;  // 수식: 속성 4 byte, 스크립트 길이 2 byte, UTF-16 스크립트, …

// FileHeader 속성 비트(한컴 hwp 5.0 형식): 0 압축, 1 암호, 2 배포용, 4 DRM, 8 공인인증서 암호화, 10 공인인증서 DRM.
constexpr std::uint32_t prop_compressed = 1U << 0;
constexpr std::uint32_t prop_locked = (1U << 1) | (1U << 2) | (1U << 4) | (1U << 8) | (1U << 10);

[[nodiscard]] constexpr std::uint32_t ctrl_id(char a, char b, char c, char d) noexcept {
    return static_cast<std::uint32_t>(a) << 24 | static_cast<std::uint32_t>(b) << 16 |
           static_cast<std::uint32_t>(c) << 8 | static_cast<std::uint32_t>(d);
}
constexpr std::array<std::uint32_t, 4> other_part_ctrls = {ctrl_id('h', 'e', 'a', 'd'), ctrl_id('f', 'o', 'o', 't'),
                                                           ctrl_id('f', 'n', ' ', ' '), ctrl_id('e', 'n', ' ', ' ')};
constexpr std::uint32_t hidden_comment_ctrl = ctrl_id('t', 'c', 'm', 't');

[[nodiscard]] std::uint32_t u32(std::string_view s, std::size_t at) {
    std::uint32_t v = 0;
    std::memcpy(&v, s.data() + at, 4);
    return v;
}

// 머리 없는 deflate(zlib windowBits -15) 풀기. 풀린 크기와 압축률을 상한으로 본다.
[[nodiscard]] std::expected<std::string, ExtractError> inflate_raw(std::string_view in, Context& context) {
    z_stream z{};
    if (inflateInit2(&z, -15) != Z_OK) {
        return std::unexpected(ExtractError::Damaged);
    }
    std::string out;
    std::array<char, 1 << 16> buf{};
    z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    z.avail_in = static_cast<uInt>(in.size());
    int rc = Z_OK;
    while (rc != Z_STREAM_END) {
        z.next_out = reinterpret_cast<Bytef*>(buf.data());
        z.avail_out = static_cast<uInt>(buf.size());
        rc = inflate(&z, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END) {
            inflateEnd(&z);
            return std::unexpected(ExtractError::Damaged);
        }
        out.append(buf.data(), buf.size() - z.avail_out);
        const auto& limits = context.limits;
        if (out.size() > limits.entry_bytes || context.unpacked + out.size() > limits.total_bytes ||
            out.size() / std::max<std::size_t>(in.size(), 1) > limits.ratio) {
            inflateEnd(&z);
            return std::unexpected(ExtractError::Bomb);
        }
        if (rc == Z_OK && z.avail_in == 0 && z.avail_out != 0) {
            inflateEnd(&z);
            return std::unexpected(ExtractError::Damaged);  // 잘린 압축
        }
    }
    inflateEnd(&z);
    context.unpacked += out.size();
    return out;
}

// PARA_TEXT 의 UTF-16 글자를 UTF-8 로. 조판 제어 문자 가운데 글자 하나짜리(0, 10, 13, 24-31)는 1 단위,
// 나머지(1-9, 11-12, 14-23)는 8 단위를 차지한다. 탭(9)은 탭, 줄 바꿈(10)·묶음 빈칸(30, 31)은 빈칸으로.
[[nodiscard]] std::expected<std::string, ExtractError> para_text(std::string_view data) {
    if (data.size() % 2 != 0) {
        return std::unexpected(ExtractError::Damaged);
    }
    std::string out;
    const auto unit = [&](std::size_t i) {
        return static_cast<char16_t>(static_cast<unsigned char>(data[2 * i]) |
                                     static_cast<unsigned char>(data[2 * i + 1]) << 8);
    };
    const std::size_t n = data.size() / 2;
    for (std::size_t i = 0; i < n;) {
        const char32_t c = unit(i);
        if (c < 32) {
            const bool single = c == 0 || c == 10 || c == 13 || c >= 24;
            if (c == 9) {
                out.push_back('\t');
            } else if (c == 10 || c == 30 || c == 31) {
                out.push_back(' ');
            }
            i += single ? 1 : 8;
            continue;
        }
        char32_t cp = c;
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < n && unit(i + 1) >= 0xDC00 && unit(i + 1) <= 0xDFFF) {
            cp = 0x10000 + ((c - 0xD800) << 10) + (unit(i + 1) - 0xDC00);
            ++i;
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            return std::unexpected(ExtractError::Damaged);
        }
        append_utf8(out, cp);
        ++i;
    }
    return out;
}

}  // namespace

std::expected<void, ExtractError> extract_hwp(const Cfb& cfb, Context& context) {
    auto header = cfb.read("FileHeader", context);
    if (!header) {
        return std::unexpected(header.error());
    }
    if (header->size() < 40 || std::string_view(*header).substr(0, 17) != "HWP Document File") {
        return std::unexpected(ExtractError::Damaged);
    }
    const auto version = u32(*header, 32);
    const auto props = u32(*header, 36);
    if (version >> 24 != 5) {
        return std::unexpected(ExtractError::Unsupported);  // hwp 3.x 등
    }
    if ((props & prop_locked) != 0) {
        return std::unexpected(ExtractError::Encrypted);
    }
    for (std::size_t section = 0;; ++section) {
        const auto name = "BodyText/Section" + std::to_string(section);
        if (!cfb.contains(name)) {
            if (section == 0) {
                return std::unexpected(ExtractError::Damaged);
            }
            break;
        }
        auto raw = cfb.read(name, context);
        if (!raw) {
            return std::unexpected(raw.error());
        }
        std::string records;
        if ((props & prop_compressed) != 0) {
            auto inflated = inflate_raw(*raw, context);
            if (!inflated) {
                return std::unexpected(inflated.error());
            }
            records = std::move(*inflated);
        } else {
            records = std::move(*raw);
        }
        std::size_t number = 0;
        std::size_t equations = 0;
        std::uint32_t skip_level = 0;
        bool skipping = false;
        for (std::size_t at = 0; at < records.size();) {
            if (records.size() - at < 4) {
                return std::unexpected(ExtractError::Damaged);
            }
            const auto head = u32(records, at);
            at += 4;
            const auto tag = head & 0x3FF;
            const auto level = head >> 10 & 0x3FF;
            std::size_t size = head >> 20;
            if (size == 0xFFF) {
                if (records.size() - at < 4) {
                    return std::unexpected(ExtractError::Damaged);
                }
                size = u32(records, at);
                at += 4;
            }
            if (size > records.size() - at) {
                return std::unexpected(ExtractError::Damaged);
            }
            const auto data = std::string_view(records).substr(at, size);
            at += size;
            if (skipping && level <= skip_level) {
                skipping = false;
            }
            if (skipping) {
                continue;
            }
            if (tag == tag_ctrl_header && data.size() >= 4) {
                const auto id = u32(data, 0);
                const bool other = std::ranges::find(other_part_ctrls, id) != other_part_ctrls.end();
                if (other || id == hidden_comment_ctrl) {
                    ++(other ? context.doc.omitted.other_parts : context.doc.omitted.comments);
                    skipping = true;
                    skip_level = level;
                }
            } else if (tag == tag_eqedit) {
                // 수식 스크립트도 본문이므로 글자로 낸다(결정 #235). 길이가 레코드를 넘으면 손상.
                if (data.size() < 6) {
                    return std::unexpected(ExtractError::Damaged);
                }
                const std::size_t length = static_cast<unsigned char>(data[4]) | static_cast<unsigned char>(data[5]) << 8;
                if (6 + 2 * length > data.size()) {
                    return std::unexpected(ExtractError::Damaged);
                }
                auto script = para_text(data.substr(6, 2 * length));
                if (!script) {
                    return std::unexpected(script.error());
                }
                if (auto r = context.add("section" + std::to_string(section) + " eq" + std::to_string(++equations),
                                         std::move(*script));
                    !r) {
                    return r;
                }
            } else if (tag == tag_para_text) {
                auto text = para_text(data);
                if (!text) {
                    return std::unexpected(text.error());
                }
                ++number;
                if (auto r = context.add("section" + std::to_string(section) + " p" + std::to_string(number),
                                         std::move(*text));
                    !r) {
                    return r;
                }
            }
        }
    }
    return {};
}

}  // namespace prompt_airlock::extract::detail
