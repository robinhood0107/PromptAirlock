// 잔여 검사 판정이 실행마다 바뀌는 원인을 나눈다(11.5-3). 게이트웨이와 같은 정책·NER·문서 조립으로 탐지하고,
// 시험용 가짜 Vault 의 seed 를 바꿔(다른 가명) 또는 고정해(같은 가명) 가명화한 뒤 다시 탐지한다.
// 같은 seed 에서도 결과가 바뀌면 원인은 가명이 아니라 탐지의 비결정성이다. 원문·값은 출력하지 않는다.
//   residual_flip_measure <cases.jsonl> <extractor> <out.jsonl>   cases 한 줄: {"id":..,"file":..,"ext":..}
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "document_writer.hpp"
#include "fake_vault.hpp"
#include "prompt_airlock/core/grade.hpp"
#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/privacy.hpp"
#include "prompt_airlock/core/residual.hpp"
#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/gateway/documents.hpp"
#include "prompt_airlock/ner/pool.hpp"

namespace core = prompt_airlock::core;
namespace detect = prompt_airlock::detect;
namespace gw = prompt_airlock::gateway;
using json = nlohmann::json;

namespace {

// 가짜 Vault 는 seed 로 정해진 결정적 token 을 낸다.
struct Scope {
    pa_test::FakeVault* vault;
    std::expected<core::Token, core::ProtectionError> issue(core::EntityType type, std::string_view value) {
        return vault->issue(type, value);
    }
    std::expected<core::SensitiveText, core::RestoreError> resolve(const core::Token& token) {
        return vault->resolve(token);
    }
};

// 추출·탐지·정책·가명화·잔여 탐지를 한 번 돈다. 정책 거절이면 그 사유, 아니면 가명 구간 밖에 남은 탐지.
json run_once(const detect::Detectors& detectors, const std::string& bytes, const std::string& ext,
              const char* extractor, std::uint64_t seed,
              std::string_view filler = core::residual_scan_filler) {
    const json body = {{"messages", json::array({{{"role", "user"}, {"content", json::array({
        {{"type", "text"}, {"text", "문서 확인 사례"}},
        {{"type", "file"}, {"file", {{"filename", "input." + ext},
            {"file_data", "data:application/octet-stream;base64," + pa_test::documents::base64(bytes)}}}}})}}})}};
    auto parsed = gw::parse_request(body.dump());
    if (!parsed) return {{"error", "parse"}};
    std::vector<gw::FileStatistics> stats;
    auto resolved = gw::resolve_documents(*parsed, extractor, stats, {});
    const auto params = core::RequestParams::create(parsed->params, core::OutputTokenCap::standard());
    const auto grade = core::resolve_grade(core::GradePolicy::OOnly, {});
    if (!resolved || !params || !grade) return {{"error", "prepare"}};
    auto raw = core::RawPrompt::create(std::move(resolved->document), *params, *grade);
    const auto detected = detectors.detect(raw.document(), {});
    if (!detected) return {{"error", "detect"}};
    auto checked = core::check_policy(std::move(raw), detected->entities, core::Policy::standard());
    if (!checked) return {{"policy", core::reason_code_name(checked.error().code())}};
    pa_test::FakeVault vault(seed);
    Scope scope{&vault};
    auto protected_prompt = core::protect(std::move(*checked), scope);
    if (!protected_prompt) return {{"error", "protect"}};
    const auto residual = detectors.detect(core::residual_scan_document(*protected_prompt, filler), {});
    if (!residual) return {{"error", "residual_detect"}};
    json left = json::array();
    const auto replacements = protected_prompt->replacements();
    for (const auto& e : residual->entities) {
        bool inside = false;
        bool touches = false;
        for (const auto& r : replacements) {
            if (r.segment != e.segment()) continue;
            inside = inside || r.span.contains(e.span());
            touches = touches || (e.span().begin() <= r.span.end() && r.span.begin() <= e.span().end());
        }
        if (!inside && core::default_action(e.type()) != core::Action::Pass) {
            left.push_back({{"type", core::entity_type_name(e.type())},
                            {"detector", static_cast<int>(e.detector())},  // DetectorKind 순서(5 = Ner)
                            {"touches_token", touches}});
        }
    }
    return {{"detected", detected->entities.size()}, {"residual", !left.empty()}, {"left", left}};
}

}  // namespace

int main(int argc, char** argv) {
    // 5번째 인자: 쉼표로 나눈 채움 글자 후보. 주면 후보마다 seed 7 로 한 번씩만 돈다.
    if (argc != 4 && argc != 5) return 2;
    std::vector<std::string> fillers;
    if (argc == 5) {
        for (std::string_view rest = argv[4]; !rest.empty();) {
            const auto comma = rest.find(',');
            fillers.emplace_back(rest.substr(0, comma));
            rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
        }
    }
    const auto ner = prompt_airlock::ner::NerPool::make(PA_NER_MODEL_DIR);
    if (!ner) return 1;
    detect::InstitutionPolicy policy;
    for (const std::string_view name :
         {"public-admin", "public-enterprise", "hospital", "human-resources", "bank", "card", "insurance"}) {
        policy.industries.push_back(*detect::industry_from_name(name));
    }
    const std::string_view terms[] = {"한빛시청", "한빛데이터"};
    const auto detectors = detect::Detectors::make(terms, *ner, policy);
    if (!detectors) return 1;
    std::ifstream in(argv[1], std::ios::binary);
    std::ofstream out(argv[3], std::ios::binary);
    for (std::string line; std::getline(in, line);) {
        if (line.empty()) continue;
        const auto item = json::parse(line);
        // 한글 경로를 윈도에서 열도록 UTF-8 로 해석한다.
        const auto name = item["file"].get<std::string>();
        std::ifstream file(std::filesystem::path(std::u8string(name.begin(), name.end())), std::ios::binary);
        const std::string bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        const std::string ext = item.value("ext", "txt");
        if (!fillers.empty()) {
            json by_filler;
            for (const auto& f : fillers) by_filler[f] = run_once(*detectors, bytes, ext, argv[2], 7, f);
            out << json{{"id", item["id"]}, {"fillers", by_filler}}.dump() << '\n';
            continue;
        }
        json varied = json::array();
        for (std::uint64_t seed = 1; seed <= 10; ++seed) varied.push_back(run_once(*detectors, bytes, ext, argv[2], seed));
        json fixed = json::array();
        for (int i = 0; i < 3; ++i) fixed.push_back(run_once(*detectors, bytes, ext, argv[2], 7));
        out << json{{"id", item["id"]}, {"varied_seeds", varied}, {"fixed_seed", fixed}}.dump() << '\n';
        std::printf("%s\n", item["id"].get<std::string>().c_str());
    }
    return 0;
}
