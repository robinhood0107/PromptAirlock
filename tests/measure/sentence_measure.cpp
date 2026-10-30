// 문장 단위 민감정보 기준선 측정(Phase 7.5-1). 기본 빌드·ctest 에 넣지 않고 직접 실행한다.
//   cmake --build <빌드 디렉터리> --target sentence_measure && <빌드 디렉터리>/tests/measure/sentence_measure [--set final] [--no-ner]
// 합성 셋(tests/fixtures/sentence)의 무리·범주마다 지금 탐지기가 막는 비율을 잰다. 막아야 하는 무리는 재현율,
// 통과해야 하는 무리(general, personal)와 NER 합성 셋의 업무 문장은 잘못 막는 비율(오차단)이다.
// 제품과 같이 NER 을 켠 탐지기를 기본으로 하고, --no-ner 는 결정론 규칙만 잰다. 통과 기준은 이 기준선을 본 뒤 정한다
// (결정 #147). 원문은 출력하지 않고 놓친 문장의 id 만 --explain 으로 낸다.
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
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--no-ner") {
            use_ner = false;
        } else if (arg == "--explain") {
            explain = true;
        } else if (arg == "--set" && i + 1 < argc && std::string_view(argv[i + 1]) == "final") {
            final_set = true;
            ++i;
        }
    }
    const fs::path sentence_dir = PA_SENTENCE_FIXTURE_DIR;
    const fs::path ner_dir = PA_NER_FIXTURE_DIR;
    auto records = load(sentence_dir / (final_set ? "sentence-final.jsonl" : "sentence-dev.jsonl"));
    const auto negatives = load_ner_negatives(ner_dir / (final_set ? "ner-final.jsonl" : "ner-large.jsonl"));
    std::printf("set: %s, sentences: %zu, ner negatives: %zu, ner: %s\n", final_set ? "final" : "dev", records.size(),
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
