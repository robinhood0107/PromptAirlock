// 원래 추출 덩어리별 검사에 같은 NER와 기관 정책을 적용한다. 원문·값 없이 종류·위치를 출력한다.
#include <cstdio>
#include <fstream>
#include <map>
#include <set>
#include <string>

#include <nlohmann/json.hpp>

#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/ner/pool.hpp"

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    namespace core = prompt_airlock::core;
    namespace detect = prompt_airlock::detect;
    using json = nlohmann::json;
    const auto ner = prompt_airlock::ner::NerPool::make(PA_NER_MODEL_DIR);
    if (!ner) return 1;
    detect::InstitutionPolicy policy;
    for (const std::string_view name : {"public-admin", "public-enterprise", "hospital", "human-resources", "bank", "card", "insurance"}) {
        const auto industry = detect::industry_from_name(name);
        if (!industry) return 1;
        policy.industries.push_back(*industry);
    }
    const std::string_view terms[] = {"한빛시청", "한빛데이터"};
    const auto detectors = detect::Detectors::make(terms, *ner, policy);
    const auto rules = detect::Detectors::make(terms, {}, policy);
    if (!detectors || !rules) return 1;
    std::ifstream in(argv[1], std::ios::binary);
    std::ofstream out(argv[2], std::ios::binary);
    if (!in || !out) return 1;
    std::size_t cases = 0, failures = 0;
    for (std::string line; std::getline(in, line);) {
        if (line.empty()) continue;
        const auto input = json::parse(line);
        std::set<std::string> blocked;
        std::map<std::string, std::size_t> counts;
        json findings = json::array();
        json entities = json::array();
        std::size_t failed_blocks = 0;
        std::size_t block_index = 0;
        for (const auto& block : input.at("blocks")) {
            const auto& scanner = input.value("ner", true) ? *detectors : *rules;
            const auto found = scanner.detect_segment(block.get_ref<const std::string&>(), core::SegmentIndex{0});
            if (!found) { ++failed_blocks; ++block_index; continue; }
            for (const auto& entity : *found) {
                ++counts[std::string(core::entity_type_name(entity.type()))];
                entities.push_back({{"block", block_index}, {"type", core::entity_type_name(entity.type())},
                                    {"begin", entity.span().begin().value()}, {"end", entity.span().end().value()}});
                if (core::default_action(entity.type()) == core::Action::Block) {
                    blocked.emplace(core::entity_type_name(entity.type()));
                    findings.push_back({{"block", block_index}, {"type", core::entity_type_name(entity.type())},
                                        {"begin", entity.span().begin().value()}, {"end", entity.span().end().value()}});
                }
            }
            ++block_index;
        }
        out << json{{"set", input.at("set")}, {"id", input.at("id")}, {"blocked_types", blocked},
                    {"failed_blocks", failed_blocks}, {"counts", counts}, {"findings", findings},
                    {"entities", entities}}.dump() << '\n';
        ++cases;
        failures += failed_blocks;
        std::printf("cases %zu failed_blocks %zu\n", cases, failures);
        std::fflush(stdout);
    }
    return 0;
}
