// 문장 단위 민감정보 기준선 측정(Phase 7.5-1). 기본 빌드·ctest 에 넣지 않고 직접 실행한다.
//   cmake --build <빌드 디렉터리> --target sentence_measure && <빌드 디렉터리>/tests/measure/sentence_measure [--set final|dev3] [--no-ner]
//                                                                 [--rules-out 파일 [--docs 폴더] [--lines 파일]]
// 합성 셋(tests/fixtures/sentence)의 무리·범주마다 지금 탐지기가 막는 비율을 잰다. 막아야 하는 무리는 재현율,
// 통과해야 하는 무리(general, personal)와 NER 합성 셋의 업무 문장은 잘못 막는 비율(오차단)이다.
// 제품과 같이 NER 을 켠 탐지기를 기본으로 하고, --no-ner 는 결정론 규칙만 잰다. 통과 기준은 이 기준선을 본 뒤 정한다
// (결정 #147). 원문은 출력하지 않고 놓친 문장의 id 만 --explain 으로 낸다.
// --rules-out 은 판별기 실험(Phase 7.7, 결정 #174)이 규칙 판정을 제품과 같은 탐지기로 받도록 문장마다 규칙 결과를 JSONL 로 쓴다.
// 셋 문장, dev3 이면 지름길 쌍(shortcut-dev3.jsonl)의 두 문장, --docs 폴더의 .txt 를 문장으로 나눈 것을 넣는다.
// --lines 는 {"id","text"} JSONL 의 줄마다 "line:<id>" 로 넣는다(정답 붙인 말뭉치 셋 평가용).
// 실제 문서(--docs)와 말뭉치(--lines)는 원문이 파일에 들어가므로 출력 파일은 저장소 밖 보호 폴더에 둔다. 화면에는 개수만 낸다.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/ner/pool.hpp"
#include "sentence_split.hpp"

namespace fs = std::filesystem;
namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pn = prompt_airlock::ner;

namespace {

struct Record {
    std::string id;
    std::string category;
    std::string group;
    std::string variant;
    std::string text;
    bool sensitive;
};

std::vector<Record> load(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::vector<Record> out;
    std::string line;
    while (std::getline(in, line)) {
        const auto j = nlohmann::json::parse(line);
        out.push_back({j.at("id").get<std::string>(), j.at("category").get<std::string>(), j.at("group").get<std::string>(),
                       j.at("variant").get<std::string>(), j.at("text").get<std::string>(), j.at("sensitive").get<bool>()});
    }
    return out;
}

// NER 합성 셋의 문장. 민감정보와 인증 정보가 없는 업무 문장이라 오차단만 센다.
std::vector<Record> load_ner_negatives(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::vector<Record> out;
    std::string line;
    while (std::getline(in, line)) {
        const auto j = nlohmann::json::parse(line);
        out.push_back({j.at("id").get<std::string>(), "None", "ner-" + j.at("category").get<std::string>(), "",
                       j.at("text").get<std::string>(), false});
    }
    return out;
}

double percentile(std::vector<double> v, double p) {
    if (v.empty()) {
        return 0.0;
    }
    std::ranges::sort(v);
    return v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))];
}

struct Tally {
    std::size_t total = 0;
    std::size_t blocked = 0;
};

}  // namespace

int main(int argc, char** argv) {
    bool use_ner = true;
    bool explain = false;
    bool final_set = false;
    bool dev3 = false;
    fs::path rules_out;
    fs::path docs;
    fs::path lines;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--no-ner") {
            use_ner = false;
        } else if (arg == "--explain") {
            explain = true;
        } else if (arg == "--set" && i + 1 < argc && std::string_view(argv[i + 1]) == "final") {
            final_set = true;
            ++i;
        } else if (arg == "--set" && i + 1 < argc && std::string_view(argv[i + 1]) == "dev3") {
            dev3 = true;
            ++i;
        } else if (arg == "--rules-out" && i + 1 < argc) {
            rules_out = argv[++i];
        } else if (arg == "--docs" && i + 1 < argc) {
            docs = argv[++i];
        } else if (arg == "--lines" && i + 1 < argc) {
            lines = argv[++i];
        }
    }
    const fs::path sentence_dir = PA_SENTENCE_FIXTURE_DIR;
    const fs::path ner_dir = PA_NER_FIXTURE_DIR;
    auto records = load(sentence_dir / (final_set ? "sentence-final.jsonl" : dev3 ? "sentence-dev3.jsonl" : "sentence-dev.jsonl"));
    // dev3 는 헷갈리는 정상 문장을 셋 안에 두므로 NER 셋 문장을 더하지 않는다.
    const auto negatives =
        dev3 ? std::vector<Record>{} : load_ner_negatives(ner_dir / (final_set ? "ner-final.jsonl" : "ner-large.jsonl"));
    std::printf("set: %s, sentences: %zu, ner negatives: %zu, ner: %s\n", final_set ? "final" : dev3 ? "dev3" : "dev", records.size(),
                negatives.size(), use_ner ? "on" : "off");
    records.insert(records.end(), negatives.begin(), negatives.end());

    std::shared_ptr<pn::NerPool> pool;
    if (use_ner) {
        auto made = pn::NerPool::make(PA_NER_MODEL_DIR);
        if (!made) {
            std::printf("NER pool unavailable\n");
            return 2;
        }
        pool = *made;
    }
    const auto detectors = *pd::Detectors::make({}, pool);

    if (!rules_out.empty()) {
        // 개인 표지(candidates.json 의 person_markers 또는 NER 사람)도 함께 쓴다. 판별기는 이것이 있을 때만 쓴다(--gate).
        std::vector<std::string> markers;
        {
            std::ifstream in(sentence_dir / "candidates.json", std::ios::binary);
            for (const auto& m : nlohmann::json::parse(in).at("person_markers")) {
                markers.push_back(m.get<std::string>());
            }
        }
        // 개인 조건 v2(person-references.json, Phase 7.8-1): 소유 표현 x 친족어, 가리키는 말 x 사람 명사, 3인칭 대명사.
        // "그 분야", "이 분기" 를 잡지 않도록 앞은 글 처음·공백·문장 부호, 뒤는 글 끝·공백·문장 부호·조사 첫 글자만 받는다.
        std::vector<std::string> references;
        {
            std::ifstream in(sentence_dir / "person-references.json", std::ios::binary);
            const auto r = nlohmann::json::parse(in);
            for (const auto& p : r.at("possessives")) {
                for (const auto& k : r.at("kin")) {
                    references.push_back(p.get<std::string>() + k.get<std::string>());
                }
            }
            for (const auto& p : r.at("pointers")) {
                for (const auto& n : r.at("nouns")) {
                    references.push_back(p.get<std::string>() + n.get<std::string>());
                }
            }
            for (const auto& p : r.at("pronouns")) {
                references.push_back(p.get<std::string>());
            }
        }
        const std::vector<std::string> particles = {"은", "는", "이", "가", "을", "를", "의", "도", "한", "에", "께", "랑", "하", "과", "와", "만", "들", "님", "네", "말", "쪽", "이랑"};
        const auto refers_to_person = [&](const std::string& text) {
            for (const auto& ref : references) {
                for (auto at = text.find(ref); at != std::string::npos; at = text.find(ref, at + 1)) {
                    const bool left = at == 0 || std::string_view(" \n\t\"'(,.:[").find(text[at - 1]) != std::string_view::npos;
                    const auto rest = std::string_view(text).substr(at + ref.size());
                    const bool right = rest.empty() || std::string_view(" \n\t\"'),.?!:;]").find(rest.front()) != std::string_view::npos ||
                                       std::ranges::any_of(particles, [&](const std::string& p) { return rest.starts_with(p); });
                    if (left && right) {
                        return true;
                    }
                }
            }
            return false;
        };
        std::ofstream out(rules_out, std::ios::binary);
        std::size_t written = 0;
        const auto write = [&](const std::string& key, const std::string& text) {
            const auto found = detectors.detect_segment(text, pc::SegmentIndex{0});
            bool person = std::ranges::any_of(markers, [&](const std::string& m) { return text.find(m) != std::string::npos; });
            bool credential = false;
            bool sensitive = false;
            std::vector<pc::ByteSpan> names;
            if (found) {
                for (const auto& e : *found) {
                    person = person || e.type() == pc::EntityType::Person;
                    credential = credential || e.type() == pc::EntityType::Credential;
                    sensitive = sensitive || e.type() == pc::EntityType::SensitivePersonalInfo;
                    if (e.type() == pc::EntityType::Person) {
                        names.push_back(e.span());
                    }
                }
            }
            // masked: NER 사람 범위를 "OOO" 로 바꾼 문장(7.6 의 이름 가리기와 같은 방식, 뒤에서부터 바꾸고 겹치면 건너뜀).
            std::ranges::sort(names, std::greater<>());
            std::string masked = text;
            std::size_t limit = masked.size();
            for (const auto& s : names) {
                if (s.end().value() <= limit) {
                    masked.replace(s.begin().value(), s.size(), "OOO");
                    limit = s.begin().value();
                }
            }
            // error 는 탐지 실패다. 제품에서는 차단이므로 실험도 막은 것으로 센다.
            out << nlohmann::json{{"key", key},
                                  {"text", text},
                                  {"masked", masked},
                                  {"error", !found},
                                  {"credential", credential},
                                  {"sensitive", sensitive},
                                  {"person", person},
                                  {"person2", person || refers_to_person(text)}}
                       .dump()
                << '\n';
            ++written;
        };
        for (const auto& r : records) {
            write(r.id, r.text);
        }
        // 학습 재료(학습 전용 셋, candidates.json 의 범주 예시와 정상 문장)도 같은 방식으로 넣는다(이름 가리기 학습용).
        for (const auto& r : load(sentence_dir / "sentence-train.jsonl")) {
            write("train:" + r.id, r.text);
        }
        {
            std::ifstream in(sentence_dir / "candidates.json", std::ios::binary);
            const auto data = nlohmann::json::parse(in);
            for (const auto& [c, v] : data.at("categories").items()) {
                std::size_t n = 0;
                for (const auto& e : v.at("examples")) {
                    write("ex:" + c + ":" + std::to_string(n++), e.get<std::string>());
                }
            }
            std::size_t n = 0;
            for (const auto& e : data.at("negatives")) {
                write("neg:" + std::to_string(n++), e.get<std::string>());
            }
        }
        if (dev3) {
            std::ifstream in(sentence_dir / "shortcut-dev3.jsonl", std::ios::binary);
            std::string line;
            for (std::size_t n = 0; std::getline(in, line); ++n) {
                const auto p = nlohmann::json::parse(line);
                write("pair" + std::to_string(n) + ":a", p.at("a").get<std::string>());
                write("pair" + std::to_string(n) + ":b", p.at("b").get<std::string>());
            }
        }
        std::size_t files = 0;
        if (!docs.empty()) {
            std::vector<fs::path> paths;
            for (const auto& e : fs::directory_iterator(docs)) {
                if (e.is_regular_file() && e.path().extension() == ".txt") {
                    paths.push_back(e.path());
                }
            }
            std::ranges::sort(paths);
            for (const auto& path : paths) {
                std::ifstream in(path, std::ios::binary);
                std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                // 메모장 등이 붙이는 UTF-8 BOM 과 Windows 줄 끝의 \r 을 뺀다.
                if (text.starts_with("\xEF\xBB\xBF")) {
                    text.erase(0, 3);
                }
                std::erase(text, '\r');
                const auto parts = split_sentences(text);
                for (std::size_t n = 0; n < parts.size(); ++n) {
                    const auto first = parts[n].find_first_not_of(" \n\t");
                    if (first == std::string::npos) {
                        continue;
                    }
                    const auto last = parts[n].find_last_not_of(" \n\t");
                    write("doc/" + path.filename().string() + "#" + std::to_string(n), parts[n].substr(first, last - first + 1));
                }
                ++files;
            }
        }
        if (!lines.empty()) {
            std::ifstream in(lines, std::ios::binary);
            std::string line;
            while (std::getline(in, line)) {
                if (line.empty()) {
                    continue;
                }
                const auto r = nlohmann::json::parse(line);
                write("line:" + r.at("id").get<std::string>(), r.at("text").get<std::string>());
            }
        }
        out.flush();
        std::printf("rules-out: %zu lines, documents %zu\n", written, files);
        return out ? 0 : 1;
    }

    std::map<std::string, Tally> by_group;
    std::map<std::string, std::map<std::string, Tally>> by_category;  // 범주 -> 무리
    std::map<std::string, Tally> by_variant;
    std::vector<double> ms;
    std::size_t errors = 0;
    for (const auto& r : records) {
        const auto start = std::chrono::steady_clock::now();
        const auto found = detectors.detect_segment(r.text, pc::SegmentIndex{0});
        ms.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
        if (!found) {
            ++errors;  // 실패는 제품에서 차단이므로 막은 것으로 센다
        }
        // 인증 정보 범주는 Credential, 나머지는 SensitivePersonalInfo 가 나와야 그 문장을 막은 것이다.
        // 통과해야 하는 문장은 둘 중 무엇이든 나오면 잘못 막은 것이다.
        bool blocked = !found;
        if (found) {
            for (const auto& e : *found) {
                const bool credential = e.type() == pc::EntityType::Credential;
                const bool sensitive = e.type() == pc::EntityType::SensitivePersonalInfo;
                if (r.sensitive ? (r.category == "Credential" ? credential : sensitive) : (credential || sensitive)) {
                    blocked = true;
                }
            }
        }
        auto& g = by_group[r.group];
        ++g.total;
        g.blocked += blocked ? 1 : 0;
        auto& c = by_category[r.category][r.group];
        ++c.total;
        c.blocked += blocked ? 1 : 0;
        if (!r.variant.empty()) {
            auto& v = by_variant[r.variant];
            ++v.total;
            v.blocked += blocked ? 1 : 0;
        }
        if (explain && blocked != r.sensitive) {
            std::printf("%s %s %s %s\n", blocked ? "false-block" : "miss", r.id.c_str(), r.category.c_str(), r.group.c_str());
        }
    }

    const auto pct = [](const Tally& t) { return t.total == 0 ? 0.0 : 100.0 * static_cast<double>(t.blocked) / static_cast<double>(t.total); };
    std::printf("\n%-16s %6s %8s %8s  %s\n", "group", "n", "blocked", "rate%", "meaning");
    for (const auto& [name, t] : by_group) {
        const bool must_block = name == "direct" || name == "variant" || name == "split" || name == "evasive";
        std::printf("%-16s %6zu %8zu %8.1f  %s\n", name.c_str(), t.total, t.blocked, pct(t), must_block ? "recall" : "false block");
    }
    std::printf("\n%-16s %6s %8s %8s\n", "variant", "n", "blocked", "rate%");
    for (const auto& [name, t] : by_variant) {
        std::printf("%-16s %6zu %8zu %8.1f\n", name.c_str(), t.total, t.blocked, pct(t));
    }
    std::printf("\nrate%% by category (blocked/n)\n%-15s", "category");
    const std::vector<std::string> groups = {"direct", "variant", "split", "evasive", "general", "personal"};
    for (const auto& g : groups) {
        std::printf(" %13s", g.c_str());
    }
    std::printf("\n");
    for (const auto& [category, row] : by_category) {
        if (category == "None") {
            continue;
        }
        std::printf("%-15s", category.c_str());
        for (const auto& g : groups) {
            const auto it = row.find(g);
            if (it == row.end()) {
                std::printf(" %13s", "-");
            } else {
                std::printf(" %5.1f (%2zu/%2zu)", pct(it->second), it->second.blocked, it->second.total);
            }
        }
        std::printf("\n");
    }
    std::printf("\nper sentence detect ms: p50 %.3f  p95 %.3f  max %.3f  (n=%zu), detector errors %zu\n", percentile(ms, 0.5),
                percentile(ms, 0.95), ms.empty() ? 0.0 : *std::ranges::max_element(ms), ms.size(), errors);
    return 0;
}
