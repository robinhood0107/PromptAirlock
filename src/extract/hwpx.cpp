// hwpx(OWPML, KS X 6101). Contents/section*.xml 의 문단(hp:p) 글자(hp:t)를 뽑는다. 메모 안 글자는 빼고 센다.
#include <algorithm>

#include "detail.hpp"

namespace prompt_airlock::extract::detail {

std::expected<void, ExtractError> extract_hwpx(const Zip& zip, Context& context) {
    // 암호화한 문서는 manifest 에 암호화 정보가 붙는다.
    if (zip.contains("META-INF/manifest.xml")) {
        auto manifest = zip.read("META-INF/manifest.xml", context);
        if (!manifest) {
            return std::unexpected(manifest.error());
        }
        if (manifest->find("encryption-data") != std::string::npos) {
            return std::unexpected(ExtractError::Encrypted);
        }
    }
    std::vector<std::string> sections;
    for (const auto& n : zip.names()) {
        if (n.starts_with("Contents/section") && n.ends_with(".xml")) {
            sections.push_back(n);
        }
    }
    if (sections.empty()) {
        return std::unexpected(ExtractError::Damaged);
    }
    std::ranges::sort(sections, natural_less);
    for (const auto& name : sections) {
        auto xml = zip.read(name, context);
        if (!xml) {
            return std::unexpected(xml.error());
        }
        const auto section = name.substr(std::string_view("Contents/").size(), name.size() - 13);
        std::string paragraph;
        std::size_t number = 0;
        int depth_in_text = 0;
        int in_memo = 0;
        std::expected<void, ExtractError> failed;
        XmlHandler h;
        h.start = [&](std::string_view n, std::span<const std::pair<std::string_view, std::string_view>>) {
            if (n == "memo") {
                ++in_memo;
                ++context.doc.omitted.comments;
            } else if (n == "t") {
                ++depth_in_text;
            } else if (n == "tab" && depth_in_text > 0) {
                paragraph.push_back('\t');
            } else if (n == "p" && depth_in_text == 0) {
                // 표 안 문단은 바깥 문단 안에 들어 있다. 안쪽 문단이 시작되면 지금까지를 먼저 낸다.
                if (!paragraph.empty()) {
                    ++number;
                    if (auto r = context.add(section + " p" + std::to_string(number), std::move(paragraph));
                        !r && failed) {
                        failed = r;
                    }
                    paragraph.clear();
                }
            }
        };
        h.end = [&](std::string_view n) {
            if (n == "memo") {
                --in_memo;
            } else if (n == "t") {
                --depth_in_text;
            } else if (n == "p") {
                ++number;
                if (auto r = context.add(section + " p" + std::to_string(number), std::move(paragraph)); !r && failed) {
                    failed = r;
                }
                paragraph.clear();
            }
        };
        h.text = [&](std::string_view s) {
            if (depth_in_text > 0 && in_memo == 0) {
                paragraph.append(s);
            }
        };
        if (auto r = parse_xml(*xml, h, context.limits.xml_depth); !r) {
            return r;
        }
        if (!failed) {
            return failed;
        }
    }
    for (const auto& n : zip.names()) {
        context.doc.omitted.other_parts += n.starts_with("Preview/") ? 1 : 0;  // 미리보기 글자·그림(본문과 겹침)
    }
    return {};
}

std::expected<void, ExtractError> extract_hwpml(std::string_view xml, Context& context) {
    // HWPML 2.x: BODY/SECTION/P/TEXT/CHAR. 문단(P)마다 CHAR 글자를 모은다. 숨은 설명(HIDDENCOMMENT)은 빼고 센다.
    std::string paragraph;
    std::size_t number = 0;
    int in_char = 0;
    int in_hidden = 0;
    std::expected<void, ExtractError> failed;
    XmlHandler h;
    h.start = [&](std::string_view n, std::span<const std::pair<std::string_view, std::string_view>>) {
        if (n == "HIDDENCOMMENT") {
            ++in_hidden;
            ++context.doc.omitted.comments;
        } else if (n == "CHAR") {
            ++in_char;
        } else if (n == "TAB" && in_char > 0) {
            paragraph.push_back('\t');
        }
    };
    h.end = [&](std::string_view n) {
        if (n == "HIDDENCOMMENT") {
            --in_hidden;
        } else if (n == "CHAR") {
            --in_char;
        } else if (n == "P") {
            ++number;
            if (auto r = context.add("p" + std::to_string(number), std::move(paragraph)); !r && failed) {
                failed = r;
            }
            paragraph.clear();
        }
    };
    h.text = [&](std::string_view s) {
        if (in_char > 0 && in_hidden == 0) {
            paragraph.append(s);
        }
    };
    if (auto r = parse_xml(xml, h, context.limits.xml_depth, true); !r) {
        return r;
    }
    return failed;
}

}  // namespace prompt_airlock::extract::detail
