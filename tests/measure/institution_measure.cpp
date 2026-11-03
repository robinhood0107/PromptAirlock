// 기관 정책 묶음 측정(Phase 11-2, 11-3). 기본 빌드·ctest 에 넣지 않고 직접 실행한다.
//   cmake --build <빌드 디렉터리> --target institution_measure
//   <빌드 디렉터리>/tests/measure/institution_measure tests/fixtures/institution/institution-dev.jsonl
//   <빌드 디렉터리>/tests/measure/institution_measure --docs <글 폴더> <저장소 밖 상세 파일>
// 문장마다 그 문장의 업종 하나만 고른 탐지기(결정론 규칙만, NER 없음)로 돌려, 무리별로
// 기밀 문장 차단 수와 기관 번호 일치 수를 센다. 원문은 출력하지 않는다(무리·업종·개수·비율만).
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <string_view>
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

// UTF-8 글자 경계로 당긴다(이어지는 byte 위면 앞으로).
std::size_t boundary(std::string_view s, std::size_t at) {
    while (at > 0 && at < s.size() && (static_cast<unsigned char>(s[at]) & 0xC0) == 0x80) {
        --at;
    }
    return at;
}

// 상세 파일 한 줄이 한 탐지가 되도록 값 안 줄바꿈·탭을 글자로 적는다.
std::string escaped(std::string_view s) {
    std::string out;
    for (const char c : s) {
        out += c == '\n' ? "\\n" : c == '\r' ? "\\r" : c == '\t' ? "\\t" : std::string(1, c);
    }
    return out;
}

// 문서 모드(11-3): 폴더의 .txt 를 4 KiB 이하 조각(줄 경계, 긴 줄은 글자 경계)으로 나눠 공공 업종 셋으로 돌린다.
// 화면에는 문서 ID 와 개수, 종류별 합계, 조각 시간만 낸다. 원문이 섞인 상세(찾은 값과 앞뒤 30 byte)는 detail 파일에만 쓴다.
int measure_documents(const std::filesystem::path& folder, const std::filesystem::path& detail_path) {
    constexpr std::size_t chunk_bytes = 4096;
    pd::InstitutionPolicy policy;
    policy.industries = {pd::Industry::PublicAdmin, pd::Industry::PublicEnterprise, pd::Industry::HumanResources};
    const auto detectors = *pd::Detectors::make({}, {}, policy);
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(folder)) {
        if (entry.path().extension() == ".txt") {
            files.push_back(entry.path());
        }
    }
    std::ranges::sort(files);
    std::ofstream detail(detail_path, std::ios::binary);
    std::vector<double> times;
    int docs_confidential = 0;
    int total_confidential = 0;
    int total_ids = 0;
    int failed = 0;
    std::map<std::string_view, int> by_type;  // 모든 종류(번호 탐지 변경 전후 비교용)
    std::printf("doc\tbytes\tchunks\tconfidential\tinstitution_ids\n");
    for (const auto& file : files) {
        std::ifstream in(file, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        int chunks = 0;
        int confidential = 0;
        int ids = 0;
        for (std::size_t at = 0; at < text.size();) {
            std::size_t end = std::min(text.size(), at + chunk_bytes);
            if (end < text.size()) {
                const auto newline = std::string_view(text).substr(at, end - at).rfind('\n');
                end = newline != std::string_view::npos && newline > 0 ? at + newline + 1 : boundary(text, end);
            }
            const std::string_view chunk = std::string_view(text).substr(at, end - at);
            const auto start = std::chrono::steady_clock::now();
            const auto found = detectors.detect_segment(chunk, pc::SegmentIndex{0});
            times.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
            ++chunks;
            if (!found) {
                ++failed;
            } else {
                for (const auto& e : *found) {
                    const bool conf = e.type() == pc::EntityType::ConfidentialMatter;
                    ++by_type[pc::entity_type_name(e.type())];
                    if (conf || e.type() == pc::EntityType::InstitutionId) {
                        (conf ? confidential : ids) += 1;
                    }
                    const auto b = e.span().begin().value();
                    const auto from = boundary(chunk, b > 30 ? b - 30 : 0);
                    const auto to = boundary(chunk, std::min(chunk.size(), b + e.span().size() + 30));
                    detail << file.stem().string() << '\t' << pc::entity_type_name(e.type()) << '\t'
                           << escaped(chunk.substr(b, e.span().size())) << '\t'
                           << escaped(chunk.substr(from, to - from)) << '\n';
                }
            }
            at = end;
        }
        docs_confidential += confidential > 0 ? 1 : 0;
        total_confidential += confidential;
        total_ids += ids;
        std::printf("%s\t%zu\t%d\t%d\t%d\n", file.stem().string().c_str(), text.size(), chunks, confidential, ids);
    }
    std::ranges::sort(times);
    const auto at = [&](double q) { return times.empty() ? 0.0 : times[static_cast<std::size_t>(q * (times.size() - 1))]; };
    std::printf("\ndocuments\t%zu\nchunks\t%zu\ndetection failures\t%d\n", files.size(), times.size(), failed);
    std::printf("documents with confidential blocks\t%d/%zu\t%.1f%%\n", docs_confidential, files.size(),
                pct(docs_confidential, static_cast<int>(files.size())));
    std::printf("confidential blocks\t%d\ninstitution ids\t%d\n", total_confidential, total_ids);
    for (const auto& [type, n] : by_type) {
        std::printf("type\t%.*s\t%d\n", static_cast<int>(type.size()), type.data(), n);
    }
    std::printf("chunk time ms p50 %.3f p95 %.3f max %.3f\n", at(0.5), at(0.95), times.empty() ? 0.0 : times.back());
    return failed == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 4 && std::string_view(argv[1]) == "--docs") {
        return measure_documents(argv[2], argv[3]);
    }
    if (argc != 2) {
        std::fputs("usage: institution_measure <set.jsonl> | --docs <folder> <detail.tsv>\n", stderr);
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
