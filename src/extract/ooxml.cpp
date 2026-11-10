// docx·xlsx·pptx(Office Open XML). 본문 글자만 뽑고 메모·지운 변경·숨긴 부분·머리글·노트는 세기만 한다.
#include <algorithm>
#include <charconv>
#include <map>
#include <optional>
#include <system_error>

#include "detail.hpp"

namespace prompt_airlock::extract::detail {
namespace {

using Attrs = std::span<const std::pair<std::string_view, std::string_view>>;

[[nodiscard]] std::optional<std::string_view> attr(Attrs attrs, std::string_view name) {
    for (const auto& [k, v] : attrs) {
        if (k == name) {
            return v;
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool truthy(std::optional<std::string_view> v) { return v && (*v == "1" || *v == "true"); }

// 이름에 prefix 로 시작하고 suffix 로 끝나는 zip 항목을 숫자 순으로.
[[nodiscard]] std::vector<std::string> parts(const Zip& zip, std::string_view prefix, std::string_view suffix) {
    std::vector<std::string> out;
    for (const auto& n : zip.names()) {
        if (n.starts_with(prefix) && n.ends_with(suffix)) {
            out.push_back(n);
        }
    }
    std::ranges::sort(out, natural_less);
    return out;
}

// 이름이 prefix 로 시작하는 항목 하나에서 element 를 센다(메모 수 등).
[[nodiscard]] std::expected<std::uint32_t, ExtractError> count_elements(const Zip& zip, std::string_view prefix,
                                                                       std::string_view element, Context& context) {
    std::uint32_t count = 0;
    for (const auto& name : parts(zip, prefix, ".xml")) {
        auto xml = zip.read(name, context);
        if (!xml) {
            return std::unexpected(xml.error());
        }
        if (auto r = parse_xml(*xml, {[&](std::string_view n, Attrs) { count += n == element ? 1 : 0; }, {}, {}},
                               context.limits.xml_depth);
            !r) {
            return std::unexpected(r.error());
        }
    }
    return count;
}

[[nodiscard]] std::uint32_t count_parts(const Zip& zip, std::initializer_list<std::string_view> prefixes) {
    std::uint32_t n = 0;
    for (const auto& name : zip.names()) {
        n += !name.ends_with('/') &&
                     std::ranges::any_of(prefixes, [&](std::string_view p) { return name.starts_with(p); }) ? 1 : 0;
    }
    return n;
}

}  // namespace

std::expected<void, ExtractError> extract_docx(const Zip& zip, Context& context) {
    auto xml = zip.read("word/document.xml", context);
    if (!xml) {
        return std::unexpected(xml.error());
    }
    std::string paragraph;
    std::size_t number = 0;
    int p_depth = 0;
    std::vector<std::uint32_t> regions;
    int in_fallback = 0;
    bool in_text = false;
    bool in_run = false;
    bool in_run_props = false;
    bool run_hidden = false;
    std::expected<void, ExtractError> failed;
    const auto flush = [&] {
        ++number;
        if (auto r = context.add("p" + std::to_string(number), std::move(paragraph)); !r && failed) {
            failed = r;
        }
        paragraph.clear();
    };
    XmlHandler h;
    h.start = [&](std::string_view n, Attrs) {
        // 글상자(w:txbxContent)는 같은 내용을 옛 판용 대체(mc:Fallback, VML)로 한 번 더 담는다. 대체 쪽은 읽지 않는다.
        if (n == "Fallback") {
            ++in_fallback;
        }
        if (in_fallback > 0) {
            return;
        }
        if (n == "tc") {
            regions.push_back(context.region);
            context.region = ++context.next_region;
        }
        if (n == "p") {
            // 글상자 문단은 바깥 문단 안에 들어 있다. 안쪽 문단이 시작되면 지금까지 모은 바깥 글을 먼저 낸다(#234).
            if (p_depth++ > 0 && !paragraph.empty()) {
                flush();
            }
        } else if (n == "r") {
            in_run = true;
            run_hidden = false;
        } else if (n == "rPr" && in_run) {
            in_run_props = true;
        } else if (n == "vanish" && in_run_props) {
            run_hidden = true;
            ++context.doc.omitted.hidden;
        } else if (n == "t") {
            in_text = !run_hidden;
        } else if (n == "tab") {
            paragraph.push_back('\t');
        } else if (n == "br") {
            paragraph.push_back(' ');
        } else if (n == "del") {
            ++context.doc.omitted.revisions;
        }
    };
    h.end = [&](std::string_view n) {
        if (in_fallback > 0) {
            in_fallback -= n == "Fallback" ? 1 : 0;
            return;
        }
        if (n == "tc" && !regions.empty()) {
            context.region = regions.back();
            regions.pop_back();
        }
        if (n == "t") {
            in_text = false;
        } else if (n == "rPr") {
            in_run_props = false;
        } else if (n == "r") {
            in_run = false;
        } else if (n == "p") {
            --p_depth;
            flush();
        }
    };
    h.text = [&](std::string_view s) {
        if (in_text && in_fallback == 0) {
            paragraph.append(s);
        }
    };
    if (auto r = parse_xml(*xml, h, context.limits.xml_depth); !r) {
        return r;
    }
    if (!failed) {
        return failed;
    }
    auto comments = count_elements(zip, "word/comments", "comment", context);
    if (!comments) {
        return std::unexpected(comments.error());
    }
    context.doc.omitted.comments += *comments;
    context.doc.omitted.other_parts +=
        count_parts(zip, {"word/header", "word/footer", "word/footnotes", "word/endnotes", "docProps/", "word/media/"});
    return {};
}

std::expected<void, ExtractError> extract_xlsx(const Zip& zip, Context& context) {
    // 공유 문자열. 발음 표기(rPh) 안의 글자는 뺀다.
    std::vector<std::string> shared;
    if (zip.contains("xl/sharedStrings.xml")) {
        auto xml = zip.read("xl/sharedStrings.xml", context);
        if (!xml) {
            return std::unexpected(xml.error());
        }
        bool in_text = false;
        int in_phonetic = 0;
        XmlHandler h;
        h.start = [&](std::string_view n, Attrs) {
            if (n == "si") {
                shared.emplace_back();
            } else if (n == "rPh") {
                ++in_phonetic;
            } else if (n == "t") {
                in_text = in_phonetic == 0 && !shared.empty();
            }
        };
        h.end = [&](std::string_view n) {
            if (n == "t") {
                in_text = false;
            } else if (n == "rPh") {
                --in_phonetic;
            }
        };
        h.text = [&](std::string_view s) {
            if (in_text) {
                shared.back().append(s);
            }
        };
        if (auto r = parse_xml(*xml, h, context.limits.xml_depth); !r) {
            return r;
        }
    }
    // 시트 목록(이름, 숨김, 관계 id) → 관계 파일로 시트 경로.
    struct Sheet {
        std::string name;
        std::string rel;
        bool hidden;
    };
    std::vector<Sheet> sheets;
    std::map<std::string, std::string, std::less<>> targets;
    for (const auto& [part, is_rels] : {std::pair{"xl/workbook.xml", false}, std::pair{"xl/_rels/workbook.xml.rels", true}}) {
        auto xml = zip.read(part, context);
        if (!xml) {
            return std::unexpected(xml.error());
        }
        XmlHandler h;
        h.start = [&](std::string_view n, Attrs a) {
            if (!is_rels && n == "sheet") {
                const auto state = attr(a, "state");
                sheets.push_back({std::string(attr(a, "name").value_or("")), std::string(attr(a, "id").value_or("")),
                                  state && *state != "visible"});
            } else if (is_rels && n == "Relationship") {
                std::string target(attr(a, "Target").value_or(""));
                target = target.starts_with('/') ? target.substr(1) : "xl/" + target;
                targets.emplace(std::string(attr(a, "Id").value_or("")), std::move(target));
            }
        };
        if (auto r = parse_xml(*xml, h, context.limits.xml_depth); !r) {
            return r;
        }
    }
    for (const auto& sheet : sheets) {
        if (sheet.hidden) {
            ++context.doc.omitted.hidden;
            continue;
        }
        const auto target = targets.find(sheet.rel);
        if (target == targets.end()) {
            return std::unexpected(ExtractError::Damaged);
        }
        auto xml = zip.read(target->second, context);
        if (!xml) {
            return std::unexpected(xml.error());
        }
        std::vector<std::string> cells;
        std::string row_number;
        std::size_t rows = 0;
        std::string cell;
        std::string type;
        bool row_hidden = false;
        bool in_value = false;
        std::expected<void, ExtractError> failed;
        XmlHandler h;
        h.start = [&](std::string_view n, Attrs a) {
            if (n == "row") {
                cells.clear();
                ++rows;
                const auto r = attr(a, "r");
                row_number = r ? std::string(*r) : std::to_string(rows);
                row_hidden = truthy(attr(a, "hidden"));
                context.doc.omitted.hidden += row_hidden ? 1 : 0;
            } else if (n == "c") {
                cell.clear();
                type = std::string(attr(a, "t").value_or("n"));
            } else if (n == "v" || n == "t") {
                in_value = true;
            }
        };
        h.end = [&](std::string_view n) {
            if (n == "v" || n == "t") {
                in_value = false;
            } else if (n == "c") {
                if (type == "s") {
                    std::size_t index = 0;
                    const auto [p, ec] = std::from_chars(cell.data(), cell.data() + cell.size(), index);
                    cell = ec == std::errc{} && p == cell.data() + cell.size() && index < shared.size() ? shared[index] : "";
                }
                cells.push_back(std::move(cell));
            } else if (n == "row" && !row_hidden) {
                for (std::size_t c = 0; c < cells.size(); ++c) {
                    const auto saved = context.region;
                    context.region = ++context.next_region;
                    auto added = context.add(sheet.name + "!" + row_number + " cell" + std::to_string(c + 1),
                                             std::move(cells[c]));
                    context.region = saved;
                    if (!added && failed) failed = added;
                }
                cells.clear();
            }
        };
        h.text = [&](std::string_view s) {
            if (in_value) {
                cell.append(s);
            }
        };
        if (auto r = parse_xml(*xml, h, context.limits.xml_depth); !r) {
            return r;
        }
        if (!failed) {
            return failed;
        }
    }
    auto comments = count_elements(zip, "xl/comments", "comment", context);
    if (!comments) {
        return std::unexpected(comments.error());
    }
    context.doc.omitted.comments += *comments;
    context.doc.omitted.other_parts += count_parts(zip, {"docProps/", "xl/media/"});
    return {};
}

std::expected<void, ExtractError> extract_pptx(const Zip& zip, Context& context) {
    for (const auto& name : parts(zip, "ppt/slides/slide", ".xml")) {
        auto xml = zip.read(name, context);
        if (!xml) {
            return std::unexpected(xml.error());
        }
        const auto slide = name.substr(std::string_view("ppt/slides/").size(), name.size() - 15);
        std::vector<std::string> paragraphs;
        std::string paragraph;
        bool hidden = false;
        bool in_text = false;
        XmlHandler h;
        h.start = [&](std::string_view n, Attrs a) {
            if (n == "sld") {
                hidden = attr(a, "show") == std::optional<std::string_view>("0");
            } else if (n == "p") {
                paragraph.clear();
            } else if (n == "t") {
                in_text = true;
            }
        };
        h.end = [&](std::string_view n) {
            if (n == "t") {
                in_text = false;
            } else if (n == "p") {
                paragraphs.push_back(std::move(paragraph));
                paragraph.clear();
            }
        };
        h.text = [&](std::string_view s) {
            if (in_text) {
                paragraph.append(s);
            }
        };
        if (auto r = parse_xml(*xml, h, context.limits.xml_depth); !r) {
            return r;
        }
        if (hidden) {
            ++context.doc.omitted.hidden;
            continue;
        }
        for (auto& p : paragraphs) {
            if (auto r = context.add(std::string(slide), std::move(p)); !r) {
                return r;
            }
        }
    }
    context.doc.omitted.comments += count_parts(zip, {"ppt/comments/"});
    context.doc.omitted.other_parts += count_parts(zip, {"ppt/notesSlides/", "docProps/", "ppt/media/"});
    return {};
}

bool natural_less(std::string_view a, std::string_view b) {
    std::size_t i = 0;
    std::size_t j = 0;
    while (i < a.size() && j < b.size()) {
        const bool da = a[i] >= '0' && a[i] <= '9';
        const bool db = b[j] >= '0' && b[j] <= '9';
        if (da && db) {
            std::size_t ei = i;
            std::size_t ej = j;
            while (ei < a.size() && a[ei] >= '0' && a[ei] <= '9') {
                ++ei;
            }
            while (ej < b.size() && b[ej] >= '0' && b[ej] <= '9') {
                ++ej;
            }
            auto na = a.substr(i, ei - i);
            auto nb = b.substr(j, ej - j);
            while (na.size() > 1 && na.front() == '0') {
                na.remove_prefix(1);
            }
            while (nb.size() > 1 && nb.front() == '0') {
                nb.remove_prefix(1);
            }
            if (na.size() != nb.size()) {
                return na.size() < nb.size();
            }
            if (na != nb) {
                return na < nb;
            }
            i = ei;
            j = ej;
            continue;
        }
        if (a[i] != b[j]) {
            return a[i] < b[j];
        }
        ++i;
        ++j;
    }
    return a.size() - i < b.size() - j;
}

}  // namespace prompt_airlock::extract::detail
