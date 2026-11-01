// 제품 문장 판별기(Phase 7.8-3) 측정: Python 과의 확률 일치, 문장 하나의 판별 시간, 메모리.
// 사용: sentence_classifier_measure <모델 폴더> <입력 JSONL {"text"}> <출력 JSONL> [계산 스레드 수]
// 입력 글을 제품과 같은 규칙으로 문장으로 나눠 문장마다 확률을 출력한다({"sentence","tokens","ms","probs"}).
// 원문이 담기므로 출력은 저장소 밖에 둔다. 표준 출력에는 집계 수치만 쓴다.
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif

#include "prompt_airlock/core/utf8.hpp"
#include "prompt_airlock/ner/sentence_classifier.hpp"

namespace {

// 지금 메모리와 최대 메모리(MB). Linux 는 최대만 잴 수 있어 둘 다 최대를 쓴다.
std::pair<double, double> memory_mb() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS c{};
    GetProcessMemoryInfo(GetCurrentProcess(), &c, sizeof c);
    return {static_cast<double>(c.WorkingSetSize) / (1024.0 * 1024.0), static_cast<double>(c.PeakWorkingSetSize) / (1024.0 * 1024.0)};
#else
    rusage u{};
    getrusage(RUSAGE_SELF, &u);
    const double peak = static_cast<double>(u.ru_maxrss) / 1024.0;
    return {peak, peak};
#endif
}

double percentile(std::vector<double> v, double q) {
    if (v.empty()) {
        return 0.0;
    }
    std::ranges::sort(v);
    return v[static_cast<std::size_t>(q * static_cast<double>(v.size() - 1))];
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 4 && argc != 5) {
        std::fprintf(stderr, "usage: sentence_classifier_measure <model dir> <input jsonl> <output jsonl> [threads]\n");
        return 2;
    }
    const auto [base_now, base_peak] = memory_mb();
    const int threads = argc == 5 ? std::atoi(argv[4]) : prompt_airlock::ner::sentence_intra_threads;
    std::printf("threads %d\n", threads);
    const auto made = prompt_airlock::ner::SentenceClassifier::make(argv[1], threads);
    if (!made) {
        std::printf("classifier unavailable (error %d)\n", static_cast<int>(made.error()));
        return 1;
    }
    const auto& classifier = **made;
    const auto [load_now, load_peak] = memory_mb();

    std::ifstream in(argv[2], std::ios::binary);
    std::ofstream out(argv[3], std::ios::binary);
    std::unordered_set<std::string> seen;
    std::vector<double> all_ms;
    std::vector<double> long_ms;  // 200 token 이상(256 token 예산 근처)
    std::size_t texts = 0;
    std::size_t errors = 0;
    for (std::string line; std::getline(in, line);) {
        if (line.empty()) {
            continue;
        }
        const auto text = nlohmann::json::parse(line).at("text").get<std::string>();
        ++texts;
        if (!prompt_airlock::core::validate_utf8(text)) {
            ++errors;
            continue;
        }
        for (const auto sentence : prompt_airlock::ner::split_sentences(text)) {
            if (!seen.emplace(sentence).second) {
                continue;
            }
            const auto start = std::chrono::steady_clock::now();
            const auto p = classifier.probabilities(sentence);
            const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
            if (!p) {
                ++errors;
                continue;
            }
            const auto units = prompt_airlock::core::decode_utf8(sentence);
            all_ms.push_back(ms);
            if (units && units->size() >= 200) {
                long_ms.push_back(ms);
            }
            out << nlohmann::json{{"sentence", sentence}, {"ms", ms}, {"probs", *p}}.dump() << '\n';
        }
    }
    // 256 token 예산: 문장 끝 표시 없이 1,000자를 넘게 이어 붙인 글은 max_tokens(256)로 잘린다. 200번 잰다.
    std::string budget;
    for (const auto& s : seen) {
        for (const char c : s) {
            budget.push_back(c == '.' || c == '?' || c == '!' || c == '\n' ? ' ' : c);
        }
        if (budget.size() > 3000) {
            break;
        }
    }
    std::vector<double> budget_ms;
    for (int i = 0; i < 200 && !budget.empty(); ++i) {
        const auto start = std::chrono::steady_clock::now();
        if (!classifier.probabilities(budget)) {
            ++errors;
            break;
        }
        budget_ms.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
    }
    const auto [end_now, end_peak] = memory_mb();
    std::printf("texts %zu, sentences %zu, errors %zu\n", texts, all_ms.size(), errors);
    std::printf("ms per sentence: p50 %.3f p95 %.3f max %.3f\n", percentile(all_ms, 0.5), percentile(all_ms, 0.95),
                all_ms.empty() ? 0.0 : *std::ranges::max_element(all_ms));
    std::printf("ms per sentence with 200+ characters (%zu): p50 %.3f p95 %.3f max %.3f\n", long_ms.size(),
                percentile(long_ms, 0.5), percentile(long_ms, 0.95),
                long_ms.empty() ? 0.0 : *std::ranges::max_element(long_ms));
    std::printf("ms per 256-token input (%zu runs, %zu bytes): p50 %.3f p95 %.3f max %.3f\n", budget_ms.size(), budget.size(),
                percentile(budget_ms, 0.5), percentile(budget_ms, 0.95),
                budget_ms.empty() ? 0.0 : *std::ranges::max_element(budget_ms));
    std::printf("memory MB: before %.1f, after load %.1f (peak %.1f), after run %.1f (peak %.1f)\n", base_now, load_now,
                load_peak, end_now, end_peak);
    std::printf("memory increase MB: after load %.1f, after run %.1f, peak %.1f\n", load_now - base_now, end_now - base_now,
                end_peak - base_peak);
    return errors == 0 ? 0 : 1;
}
