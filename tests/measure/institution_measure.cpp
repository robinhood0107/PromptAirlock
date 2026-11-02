// 기관 정책 묶음 측정(Phase 11-2, 11-3). 기본 빌드·ctest 에 넣지 않고 직접 실행한다.
//   cmake --build <빌드 디렉터리> --target institution_measure
//   <빌드 디렉터리>/tests/measure/institution_measure tests/fixtures/institution/institution-dev.jsonl
// 문장마다 그 문장의 업종 하나만 고른 탐지기(결정론 규칙만, NER 없음)로 돌려, 무리별로
// 기밀 문장 차단 수와 기관 번호 일치 수를 센다. 원문은 출력하지 않는다(무리·업종·개수·비율만).
#include <chrono>
#include <cstdio>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "prompt_airlock/detect/detectors.hpp"

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;

namespace {

struct Count {
    int n = 0;
    int confidential = 0;  // CONFIDENTIAL_MATTER 가 하나라도 나온 문장
    int ids_expected = 0;
    int ids_found = 0;     // 기대한 번호가 정확히 INSTITUTION_ID 로 나온 수
    int ids_extra = 0;     // 기대하지 않은 INSTITUTION_ID 수
};

double pct(int a, int b) { return b == 0 ? 0.0 : 100.0 * a / b; }

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fputs("usage: institution_measure <set.jsonl>\n", stderr);
        return 2;
    }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) {
        std::fputs("cannot read the set\n", stderr);
        return 2;
    }
    std::map<std::string, pd::Detectors> detectors;
    std::map<std::pair<std::string, std::string>, Count> counts;  // (무리, 업종)
    std::map<std::string, Count> groups;
    double total_ms = 0;
    int sentences = 0;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        const auto r = nlohmann::json::parse(line);
        const std::string industry = r["industry"];
        const std::string group = r["group"];
        const std::string text = r["text"];
        if (!detectors.contains(industry)) {
            pd::InstitutionPolicy policy;
            policy.industries = {*pd::industry_from_name(industry)};
            detectors.emplace(industry, *pd::Detectors::make({}, {}, policy));
        }
        const auto start = std::chrono::steady_clock::now();
        const auto found = detectors.at(industry).detect_segment(text, pc::SegmentIndex{0});
        total_ms += std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        ++sentences;
        if (!found) {
            std::fputs("detection failed\n", stderr);
            return 1;
        }
        std::vector<std::string> ids;
        bool confidential = false;
        for (const auto& e : *found) {
            confidential = confidential || e.type() == pc::EntityType::ConfidentialMatter;
            if (e.type() == pc::EntityType::InstitutionId) {
                ids.push_back(text.substr(e.span().begin().value(), e.span().size()));
            }
        }
        int expected_found = 0;
        for (const auto& v : r["ids"]) {
            expected_found += std::ranges::find(ids, v.get<std::string>()) != ids.end() ? 1 : 0;
        }
        for (auto* c : {&counts[{group, industry}], &groups[group]}) {
            ++c->n;
            c->confidential += confidential ? 1 : 0;
            c->ids_expected += static_cast<int>(r["ids"].size());
            c->ids_found += expected_found;
            c->ids_extra += static_cast<int>(ids.size()) - expected_found;
        }
    }

    std::printf("group\tindustry\tn\tconfidential\tids_expected\tids_found\tids_extra\n");
    for (const auto& [key, c] : counts) {
        std::printf("%s\t%s\t%d\t%d\t%d\t%d\t%d\n", key.first.c_str(), key.second.c_str(), c.n, c.confidential,
                    c.ids_expected, c.ids_found, c.ids_extra);
    }
    std::printf("\ngroup\tn\tconfidential\tids_expected\tids_found\tids_extra\n");
    for (const auto& [g, c] : groups) {
        std::printf("%s\t%d\t%d\t%d\t%d\t%d\n", g.c_str(), c.n, c.confidential, c.ids_expected, c.ids_found,
                    c.ids_extra);
    }
    const auto& conf = groups["conf"];
    const auto& split = groups["conf_split"];
    const auto& para = groups["conf_para"];
    int negatives = 0;
    int false_blocks = 0;
    for (const auto* g : {"far", "marker_only", "subject_only", "business", "id", "id_neg"}) {
        negatives += groups[g].n;
        false_blocks += groups[g].confidential;
    }
    int id_negatives = 0;
    int id_false = 0;
    for (const auto* g : {"id_neg", "business", "conf", "conf_split", "conf_para", "far", "marker_only", "subject_only"}) {
        id_negatives += groups[g].n;
        id_false += groups[g].ids_extra;
    }
    std::printf("\nconfidential recall (conf + conf_split)\t%d/%d\t%.1f%%\n", conf.confidential + split.confidential,
                conf.n + split.n, pct(conf.confidential + split.confidential, conf.n + split.n));
    std::printf("confidential recall (conf_para, paraphrased subject)\t%d/%d\t%.1f%%\n", para.confidential, para.n,
                pct(para.confidential, para.n));
    std::printf("confidential false block (far, marker_only, subject_only, business, id, id_neg)\t%d/%d\t%.1f%%\n",
                false_blocks, negatives, pct(false_blocks, negatives));
    std::printf("institution id recall (exact)\t%d/%d\t%.1f%%\n", groups["id"].ids_found, groups["id"].ids_expected,
                pct(groups["id"].ids_found, groups["id"].ids_expected));
    std::printf("institution id extra in id groups\t%d\n", groups["id"].ids_extra);
    std::printf("institution id false (sentences without expected ids)\t%d/%d sentences\n", id_false, id_negatives);
    std::printf("mean detect time per sentence\t%.3f ms (%d sentences)\n", total_ms / sentences, sentences);
    return 0;
}
