// NER 측정(Phase 7-3). 기본 빌드·ctest 에 넣지 않고 직접 실행한다.
//   cmake --build <빌드 디렉터리> --target ner_measure && <빌드 디렉터리>/tests/measure/ner_measure
// 큰 합성 셋 900문장으로 다음을 잰다. 기본은 개발용(ner-large.jsonl), --set heldout 이면 판정용(ner-heldout.jsonl).
// 합격 판정은 판정용 셋으로만 한다(결정 #107).
//   1. 메모리: worker 2개 pool 의 최대 상주 메모리
//   2. 정확도: NER 엔진(NFKC 보기)의 정확 일치 재현율·정밀도와 위치 오류, 경우별 재현율, NFKC 와 NFC 비교.
//      탐지기 전체(결정론 기관 규칙 + NER)의 정확 일치 재현율과 이름이 가려진 비율도 함께 잰다.
//   3. 지연: 짧은 문장, 256 token(합격 기준 길이), 긴 글(창 여러 개), 콜드 스타트
//   4. 부하: 동시 8개 꾸준한 요청, 동시 32개 몰림, 가장 큰 일 8개 몰림(대기 상한 10초 확인)
//   5. 잔여 검사(Vault 가 있을 때): 900문장을 실제 Vault 로 보호한 뒤 다시 탐지해 거절 수와 이름 원문 유출 수
// 합성 문장의 id 와 경우만 출력한다. --explain 을 주면 놓친 문장과 잔여 검사에서 거절된 문장의 글·예측·찾은 항목을 함께
// 찍는다(모두 합성 문장이라 원인 분석용으로 로컬에서만 본다). 기준을 하나라도 넘으면 종료 코드 1.
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif

#include <utf8proc.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <latch>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "prompt_airlock/core/utf8.hpp"
#include "prompt_airlock/detect/detectors.hpp"
#include "prompt_airlock/detect/view.hpp"
#include "prompt_airlock/ner/engine.hpp"
#include "prompt_airlock/ner/model_files.hpp"
#include "prompt_airlock/ner/pool.hpp"
#include "prompt_airlock/ner/tokenizer.hpp"
#include "prompt_airlock/ner/windows.hpp"

#ifdef PA_MEASURE_WITH_VAULT
#include "prompt_airlock/core/grade.hpp"
#include "prompt_airlock/core/policy.hpp"
#include "prompt_airlock/core/privacy.hpp"
#include "prompt_airlock/core/reason.hpp"
#include "prompt_airlock/core/residual.hpp"
#include "prompt_airlock/vault_client/service.hpp"
#endif

namespace fs = std::filesystem;
namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
namespace pn = prompt_airlock::ner;

namespace {

struct Gold {
    pc::EntityType type;
    std::string text;
    std::size_t begin;
    std::size_t end;
};

struct Record {
    std::string id;
    std::string variant;
    std::string text;
    std::vector<Gold> gold;
};

std::vector<Record> load(const char* file) {
    std::ifstream in(fs::path(PA_NER_FIXTURE_DIR) / file, std::ios::binary);
    std::vector<Record> out;
    std::string line;
    while (std::getline(in, line)) {
        const auto j = nlohmann::json::parse(line);
        Record r{j.at("id").get<std::string>(), j.at("variant").get<std::string>(), j.at("text").get<std::string>(), {}};
        for (const auto& e : j.at("entities")) {
            const auto type = e.at("type").get<std::string>() == "PERSON" ? pc::EntityType::Person
                                                                         : pc::EntityType::Organization;
            r.gold.push_back({type, e.at("text").get<std::string>(), e.at("start_byte").get<std::size_t>(),
                              e.at("end_byte").get<std::size_t>()});
        }
        out.push_back(std::move(r));
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

double time_ms(const std::function<void()>& fn) {
    const auto start = std::chrono::steady_clock::now();
    fn();
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
}

void row(const char* name, const std::vector<double>& ms) {
    std::printf("%-46s p50 %9.3f  p95 %9.3f  max %9.3f  (n=%zu)\n", name, percentile(ms, 0.5), percentile(ms, 0.95),
                ms.empty() ? 0.0 : *std::ranges::max_element(ms), ms.size());
}

bool report(const char* name, double value, double limit, bool upper = true) {
    const bool ok = upper ? value <= limit : value >= limit;
    std::printf("%-46s %10.3f  %s %8.3f  %s\n", name, value, upper ? "<=" : ">=", limit, ok ? "PASS" : "FAIL");
    return ok;
}

double peak_mb() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS c{};
    GetProcessMemoryInfo(GetCurrentProcess(), &c, sizeof c);
    return static_cast<double>(c.PeakWorkingSetSize) / (1024.0 * 1024.0);
#else
    rusage u{};
    getrusage(RUSAGE_SELF, &u);
    return static_cast<double>(u.ru_maxrss) / 1024.0;  // Linux 는 KiB
#endif
}

struct FreeDeleter {
    void operator()(utf8proc_uint8_t* p) const noexcept { std::free(p); }
};

[[nodiscard]] constexpr bool is_zero_width(char32_t c) noexcept {
    return c == 0x200B || c == 0x200C || c == 0x200D || c == 0x2060 || c == 0xFEFF;
}

// 제품 보기와 같게 zero-width 를 빼되 NFKC 대신 NFC 만 한 글(비교용).
std::string nfc_view_text(std::string_view text) {
    const auto units = pc::decode_utf8(text);
    std::string filtered;
    for (const auto& u : *units) {
        if (!is_zero_width(u.value)) {
            filtered.append(text.substr(u.source.begin().value(), u.source.size()));
        }
    }
    utf8proc_uint8_t* raw = nullptr;
    const auto n = utf8proc_map(reinterpret_cast<const utf8proc_uint8_t*>(filtered.data()),
                                static_cast<utf8proc_ssize_t>(filtered.size()), &raw,
                                static_cast<utf8proc_option_t>(UTF8PROC_STABLE | UTF8PROC_COMPOSE));
    const std::unique_ptr<utf8proc_uint8_t, FreeDeleter> owned(raw);
    return n < 0 ? std::string{} : std::string(reinterpret_cast<const char*>(owned.get()), static_cast<std::size_t>(n));
}

// 정규화 방식과 상관없이 비교할 수 있게 표면을 NFC + zero-width 제거로 맞춘다.
std::string canonical(std::string_view surface) { return nfc_view_text(surface); }

struct Counts {
    std::size_t tp = 0, fp = 0, fn = 0;
    [[nodiscard]] double precision() const { return tp + fp == 0 ? 1.0 : static_cast<double>(tp) / static_cast<double>(tp + fp); }
    [[nodiscard]] double recall() const { return tp + fn == 0 ? 1.0 : static_cast<double>(tp) / static_cast<double>(tp + fn); }
};

using Key = std::pair<pc::EntityType, std::string>;

// 문장 하나의 (종류, 표면) 묶음을 정답과 비교한다(같은 표면이 여러 번이면 개수까지).
void score_strings(const std::multiset<Key>& predicted, const std::multiset<Key>& gold, std::map<pc::EntityType, Counts>& out) {
    std::multiset<Key> left = gold;
    for (const auto& p : predicted) {
        if (const auto it = left.find(p); it != left.end()) {
            ++out[p.first].tp;
            left.erase(it);
        } else {
            ++out[p.first].fp;
        }
    }
    for (const auto& g : left) {
        ++out[g.first].fn;
    }
}

std::multiset<Key> gold_keys(const Record& r) {
    std::multiset<Key> out;
    for (const auto& g : r.gold) {
        out.insert({g.type, canonical(g.text)});
    }
    return out;
}

// tokenizer 로 센 토큰 수가 limit(special 포함)를 넘지 않게 문장을 이어 붙인 글들.
std::vector<std::string> texts_near(const std::vector<Record>& records, const pn::WordPieceTokenizer& tokenizer,
                                    std::size_t limit, std::size_t count) {
    std::vector<std::string> out;
    std::size_t next = 0;
    while (out.size() < count) {
        std::string text;
        for (;;) {
            const auto candidate = text + records[next % records.size()].text + " ";
            const auto view = pd::make_view(candidate);
            if (tokenizer.encode(view->units).size() > limit) {
                break;
            }
            text = candidate;
            next += 7;  // 같은 순서가 반복되지 않게 건너뛴다
        }
        out.push_back(text);
    }
    return out;
}

struct LoadResult {
    std::vector<double> ms;
    std::size_t ok = 0, overloaded = 0, timeout = 0, other = 0;
    double wall_ms = 0.0;
};

// threads 개가 동시에 출발해 각자 rounds 번 text 를 넣는다.
LoadResult run_load(const pn::NerPool& pool, const std::vector<std::string>& texts, int threads, int rounds) {
    std::vector<pd::DetectionView> views;
    for (const auto& t : texts) {
        views.push_back(*pd::make_view(t));
    }
    LoadResult result;
    std::mutex mutex;
    std::latch start(threads);
    const auto begin = std::chrono::steady_clock::now();
    std::vector<std::thread> callers;
    for (int t = 0; t < threads; ++t) {
        callers.emplace_back([&, t] {
            start.arrive_and_wait();
            for (int i = 0; i < rounds; ++i) {
                const auto k = static_cast<std::size_t>(t * rounds + i) % texts.size();
                std::expected<std::vector<pc::EntitySpan>, pc::DetectError> found;
                const auto ms = time_ms([&] { found = pool.scan(texts[k], pc::SegmentIndex{0}, views[k]); });
                const std::lock_guard lock(mutex);
                result.ms.push_back(ms);
                if (found) {
                    ++result.ok;
                } else if (found.error() == pc::DetectError::Overloaded) {
                    ++result.overloaded;
                } else if (found.error() == pc::DetectError::Timeout) {
                    ++result.timeout;
                } else {
                    ++result.other;
                }
            }
        });
    }
    for (auto& c : callers) {
        c.join();
    }
    result.wall_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - begin).count();
    return result;
}

void print_load(const char* name, const LoadResult& r) {
    row(name, r.ms);
    std::printf("%-46s ok %zu  overloaded %zu  timeout %zu  other %zu  wall %.0f ms\n", "", r.ok, r.overloaded, r.timeout,
                r.other, r.wall_ms);
}

#ifdef PA_MEASURE_WITH_VAULT
struct Residual {
    bool verified = false;
    std::string sent;  // 보호한 뒤 provider 로 나갈 글
    std::string why;   // 거절 사유와 잔여 검사가 찾은 항목(--explain)
    bool policy_blocked = false;  // 보호 전에 정책(차단 종류)에서 막힘. 잔여 검사 거절과 따로 센다
};

// 탐지 → 정책 → 범위 → 보호 → 다시 탐지 → 잔여 검사(provider 요청 직전까지).
Residual protect(const pd::Detectors& detectors, prompt_airlock::vault_client::VaultService& service,
                 std::string_view text) {
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts));
    auto raw = pc::RawPrompt::create(*std::move(builder).build(),
                                     *pc::RequestParams::create({}, pc::OutputTokenCap::standard()),
                                     *pc::resolve_grade(pc::GradePolicy::OOnly, {}));
    const auto detected = detectors.detect(raw.document());
    if (!detected) {
        return {false, {}, "detect failed"};
    }
    auto checked = pc::check_policy(std::move(raw), detected->entities, pc::Policy::standard());
    if (!checked) {
        return {false, {}, std::string(pc::reason_code_name(checked.error().code())), true};
    }
    auto scope = service.open_scope();
    if (!scope) {
        return {false, {}, "vault unavailable"};
    }
    auto protected_prompt = pc::protect(std::move(*checked), *scope);
    if (!protected_prompt) {
        return {false, {}, "protect failed"};
    }
    Residual out;
    out.sent = std::string(protected_prompt->document().segments()[0].text());
    const auto residual = detectors.detect(protected_prompt->document());
    if (!residual) {
        out.why = "residual detect failed";
        return out;
    }
    const auto verified =
        pc::verify_residual(std::move(*protected_prompt), pc::ResidualReport{residual->entities, residual->encoded});
    out.verified = verified.has_value();
    if (!verified) {
        out.why = std::string(pc::reason_code_name(verified.error().code()));
        for (const auto& f : verified.error().for_audit().findings) {
            if (const auto* e = std::get_if<pc::EntityFinding>(&f)) {
                out.why += " " + std::string(pc::entity_type_name(e->type)) + "[" +
                           out.sent.substr(e->span.begin().value(), e->span.size()) + "]";
            }
        }
    }
    return out;
}
#endif

}  // namespace

int main(int argc, char** argv) {
    bool explain = false;
    int residual_runs = 1;  // 가명 token 이 무작위라 잔여 검사 결과가 실행마다 다를 수 있어 여러 번 돈다
    bool accuracy_only = false;  // 지연·부하·잔여 검사를 건너뛴다(개발용 셋으로 후처리를 다듬을 때)
    const char* file = "ner-large.jsonl";
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--explain") {
            explain = true;
        } else if (arg == "--set" && i + 1 < argc && std::string_view(argv[i + 1]) == "heldout") {
            file = "ner-heldout.jsonl";
            ++i;
        } else if (arg == "--accuracy-only") {
            accuracy_only = true;
        } else if (arg == "--residual-runs" && i + 1 < argc) {
            residual_runs = std::max(1, std::atoi(argv[i + 1]));
            ++i;
        }
    }
    const fs::path model_dir = PA_NER_MODEL_DIR;
    const auto records = load(file);
    bool ok = true;
    std::printf("set: %s, records: %zu\n", file, records.size());

    // 1. 메모리: 모델을 읽기 전과 pool(worker 2개)을 띄워 몇 번 돌린 뒤의 최대 상주 메모리.
    const double base_mb = peak_mb();
    std::shared_ptr<pn::NerPool> pool;
    const auto pool_start_ms = time_ms([&] { pool = *pn::NerPool::make(model_dir); });
    for (std::size_t i = 0; i < 20; ++i) {
        const auto view = pd::make_view(records[i].text);
        (void)pool->scan(records[i].text, pc::SegmentIndex{0}, *view);
    }
    const double pool_mb = peak_mb();
    std::printf("%-46s %10.1f\n", "peak memory before model (MB)", base_mb);
    std::printf("%-46s %10.1f\n", "peak memory with pool, 2 workers (MB)", pool_mb);
    std::printf("%-46s %10.1f  (참고, 계획 약 210)\n", "pool memory (MB)", pool_mb - base_mb);
    std::printf("%-46s %10.1f\n", "pool start, 2 sessions (ms)", pool_start_ms);

    // 2. 정확도. 엔진 하나로 순서대로 돈다.
    auto engine = *pn::NerEngine::make(model_dir);
    std::map<pc::EntityType, Counts> exact, nfkc_strings, nfc_strings;
    std::map<std::string, std::pair<std::size_t, std::size_t>> by_variant;  // 경우별 (찾음, 전체)
    std::map<pc::EntityType, std::pair<std::size_t, std::size_t>> covered;  // (덮인 정답, 전체 정답)
    std::size_t offset_errors = 0;
    std::size_t negative_hits = 0;
    std::vector<std::string> misses;
    for (const auto& r : records) {
        const auto view = pd::make_view(r.text);
        const auto found = engine.detect_all(r.text, pc::SegmentIndex{0}, *view);
        if (!found) {
            ++offset_errors;  // 위치 불일치(InvalidSpan) 와 그 밖의 실패를 모두 센다
            continue;
        }
        std::set<std::tuple<pc::EntityType, std::size_t, std::size_t>> predicted;
        std::multiset<Key> predicted_strings;
        for (const auto& e : *found) {
            if (!pc::check_span(r.text, e.span())) {
                ++offset_errors;
            }
            predicted.insert({e.type(), e.span().begin().value(), e.span().end().value()});
            predicted_strings.insert(
                {e.type(), canonical(std::string_view(r.text).substr(e.span().begin().value(), e.span().size()))});
        }
        if (r.gold.empty()) {
            negative_hits += found->size();
        }
        // 정확 일치: 정답과 위치·종류가 같으면 tp, 남는 예측은 fp, 남는 정답은 fn.
        std::set<std::tuple<pc::EntityType, std::size_t, std::size_t>> gold;
        for (const auto& g : r.gold) {
            const bool hit = predicted.contains({g.type, g.begin, g.end});
            gold.insert({g.type, g.begin, g.end});
            ++(hit ? exact[g.type].tp : exact[g.type].fn);
            // 덮임: 같은 종류의 탐지 구간이 정답 전체를 덮으면 가명화로 가려진다(경계가 더 넓어도 보호는 된다).
            const bool cover = std::ranges::any_of(predicted, [&](const auto& x) {
                return std::get<0>(x) == g.type && std::get<1>(x) <= g.begin && g.end <= std::get<2>(x);
            });
            covered[g.type].first += cover;
            ++covered[g.type].second;
            auto& v = by_variant[(g.type == pc::EntityType::Person ? "person/" : "org/") + r.variant];
            v.first += hit;
            ++v.second;
            if (!hit) {
                misses.push_back(r.id + "(" + r.variant + ")");
                if (explain) {
                    std::printf("MISS %s %s gold[%s] predicted:", r.id.c_str(), r.text.c_str(), g.text.c_str());
                    for (const auto& e : *found) {
                        std::printf(" %s[%s]", std::string(pc::entity_type_name(e.type())).c_str(),
                                    r.text.substr(e.span().begin().value(), e.span().size()).c_str());
                    }
                    std::printf("\n");
                }
            }
        }
        for (const auto& p : predicted) {
            if (!gold.contains(p)) {
                ++exact[std::get<0>(p)].fp;
            }
        }
        score_strings(predicted_strings, gold_keys(r), nfkc_strings);

        // NFC 비교: 같은 엔진에 NFC 만 한 글을 넣는다.
        const auto nfc_text = nfc_view_text(r.text);
        const auto nfc_units = pc::decode_utf8(nfc_text);
        const pd::DetectionView nfc_view{*nfc_units};
        const auto nfc_found = engine.detect_all(nfc_text, pc::SegmentIndex{0}, nfc_view);
        std::multiset<Key> nfc_predicted;
        if (nfc_found) {
            for (const auto& e : *nfc_found) {
                nfc_predicted.insert(
                    {e.type(), canonical(std::string_view(nfc_text).substr(e.span().begin().value(), e.span().size()))});
            }
        }
        score_strings(nfc_predicted, gold_keys(r), nfc_strings);
    }
    const auto& person = exact[pc::EntityType::Person];
    const auto& org = exact[pc::EntityType::Organization];
    std::printf("\n%-46s tp %zu fp %zu fn %zu  P %.3f R %.3f\n", "PERSON exact (NFKC, product)", person.tp, person.fp,
                person.fn, person.precision(), person.recall());
    std::printf("%-46s tp %zu fp %zu fn %zu  P %.3f R %.3f\n", "ORG exact (NFKC, product)", org.tp, org.fp, org.fn,
                org.precision(), org.recall());
    ok &= report("offset errors (count)", static_cast<double>(offset_errors), 0.0);
    ok &= report("PERSON recall (exact)", person.recall(), 0.9, false);
    ok &= report("ORG recall (exact)", org.recall(), 0.8, false);
    const auto cover_rate = [&](pc::EntityType t) {
        return static_cast<double>(covered[t].first) / static_cast<double>(std::max<std::size_t>(covered[t].second, 1));
    };
    std::printf("%-46s %10.3f  (%zu / %zu, 정답 전체가 같은 종류 구간에 덮임)\n", "PERSON recall (covered)",
                cover_rate(pc::EntityType::Person), covered[pc::EntityType::Person].first, covered[pc::EntityType::Person].second);
    std::printf("%-46s %10.3f  (%zu / %zu)\n", "ORG recall (covered)", cover_rate(pc::EntityType::Organization),
                covered[pc::EntityType::Organization].first, covered[pc::EntityType::Organization].second);
    std::printf("%-46s %10zu  (참고, 이름 없는 문장 300개에서 찾은 수)\n", "names found in negatives", negative_hits);
    for (const auto t : {pc::EntityType::Person, pc::EntityType::Organization}) {
        const auto& k = nfkc_strings[t];
        const auto& c = nfc_strings[t];
        const char* name = t == pc::EntityType::Person ? "PERSON" : "ORG";
        std::printf("%-6s surface match  NFKC P %.3f R %.3f | NFC P %.3f R %.3f\n", name, k.precision(), k.recall(),
                    c.precision(), c.recall());
        ok &= report((std::string(name) + " NFC precision - NFKC precision (%p)").c_str(),
                     100.0 * (c.precision() - k.precision()), 2.0);
    }
    std::printf("\nrecall by case (exact)\n");
    for (const auto& [variant, v] : by_variant) {
        std::printf("  %-28s %4zu / %-4zu %.3f\n", variant.c_str(), v.first, v.second,
                    static_cast<double>(v.first) / static_cast<double>(v.second));
    }
    std::printf("missed (id, case): ");
    for (std::size_t i = 0; i < misses.size() && i < 40; ++i) {
        std::printf("%s ", misses[i].c_str());
    }
    std::printf("%s\n", misses.size() > 40 ? "..." : "");

    // 2-2. 탐지기 전체. 사용자 요청에서 이름이 실제로 가려지는지는 이 값이 정한다.
    {
        const auto product = *pd::Detectors::make({}, pool);
        std::map<pc::EntityType, std::pair<std::size_t, std::size_t>> hit, masked;  // (맞음, 전체)
        std::size_t product_negative = 0;
        std::vector<std::string> product_misses;
        for (const auto& r : records) {
            const auto found = product.detect_segment(r.text, pc::SegmentIndex{0});
            if (!found) {
                ok = false;
                continue;
            }
            std::vector<pc::EntitySpan> names;
            for (const auto& e : *found) {
                if (e.type() == pc::EntityType::Person || e.type() == pc::EntityType::Organization) {
                    names.push_back(e);
                }
            }
            if (r.gold.empty()) {
                product_negative += names.size();
            }
            for (const auto& g : r.gold) {
                const bool exact_hit = std::ranges::any_of(names, [&](const pc::EntitySpan& e) {
                    return e.type() == g.type && e.span().begin().value() == g.begin && e.span().end().value() == g.end;
                });
                // 가려짐: 종류와 상관없이 어떤 탐지 구간이 정답 전체를 덮는다(가명화되어 원문이 나가지 않는다).
                const bool cover = std::ranges::any_of(*found, [&](const pc::EntitySpan& e) {
                    return e.span().begin().value() <= g.begin && g.end <= e.span().end().value();
                });
                hit[g.type].first += exact_hit;
                ++hit[g.type].second;
                masked[g.type].first += cover;
                ++masked[g.type].second;
                if (!cover) {
                    product_misses.push_back(r.id + "(" + r.variant + ")");
                    if (explain) {
                        std::printf("LEAK %s %s gold[%s]\n", r.id.c_str(), r.text.c_str(), g.text.c_str());
                    }
                }
            }
        }
        const auto rate = [](const std::pair<std::size_t, std::size_t>& v) {
            return static_cast<double>(v.first) / static_cast<double>(std::max<std::size_t>(v.second, 1));
        };
        std::printf("\n");
        ok &= report("product PERSON recall (exact)", rate(hit[pc::EntityType::Person]), 0.9, false);
        ok &= report("product ORG recall (exact)", rate(hit[pc::EntityType::Organization]), 0.8, false);
        std::printf("%-46s %10.3f  (%zu / %zu, 원문이 그대로 나가지 않음)\n", "product PERSON masked",
                    rate(masked[pc::EntityType::Person]), masked[pc::EntityType::Person].first,
                    masked[pc::EntityType::Person].second);
        std::printf("%-46s %10.3f  (%zu / %zu)\n", "product ORG masked", rate(masked[pc::EntityType::Organization]),
                    masked[pc::EntityType::Organization].first, masked[pc::EntityType::Organization].second);
        std::printf("%-46s %10zu  (참고, 이름 없는 문장 300개에서 사람·기관으로 찾은 수)\n", "product names in negatives",
                    product_negative);
        std::printf("product not masked (id, case): ");
        for (const auto& m : product_misses) {
            std::printf("%s ", m.c_str());
        }
        std::printf("\n");
    }

    if (accuracy_only) {
        return ok ? 0 : 1;
    }

    // 3. 지연(단일 스레드, 정규화 + tokenize + 추론 + 결과 묶기 전체).
    const auto files = *pn::read_verified_model_files(model_dir);
    const auto tokenizer = *pn::WordPieceTokenizer::parse(files.tokenizer);
    std::vector<double> short_ms;
    for (const auto& r : records) {
        short_ms.push_back(time_ms([&] {
            const auto view = pd::make_view(r.text);
            (void)engine.detect_all(r.text, pc::SegmentIndex{0}, *view);
        }));
    }
    std::printf("\n");
    row("one sentence (ms)", short_ms);
    const auto texts256 = texts_near(records, tokenizer, 256, 50);
    std::vector<double> ms256;
    for (int rep = 0; rep < 4; ++rep) {
        for (const auto& t : texts256) {
            ms256.push_back(time_ms([&] {
                const auto view = pd::make_view(t);
                (void)engine.detect_all(t, pc::SegmentIndex{0}, *view);
            }));
        }
    }
    row("256 tokens (ms)", ms256);
    ok &= report("256 tokens p95 (ms)", percentile(ms256, 0.95), 200.0);

    for (const std::size_t tokens : {2'048U, 8'192U}) {
        const auto t = texts_near(records, tokenizer, tokens, 1).front();
        std::vector<double> ms;
        for (int rep = 0; rep < 3; ++rep) {
            ms.push_back(time_ms([&] {
                const auto view = pd::make_view(t);
                (void)engine.detect_all(t, pc::SegmentIndex{0}, *view);
            }));
        }
        row(("sentences up to " + std::to_string(tokens) + " tokens (ms)").c_str(), ms);
    }
    // 가장 큰 일: 문장 끝 없는 글로 창을 128개(상한) 채운다.
    std::string worst;
    const std::uint32_t step = pn::window_body_tokens - pn::window_overlap_tokens;
    for (std::uint32_t i = 0; i < pn::window_body_tokens + step * (pn::max_ner_windows - 1); ++i) {
        worst += "가 ";
    }
    std::vector<double> worst_ms;
    for (int rep = 0; rep < 3; ++rep) {
        worst_ms.push_back(time_ms([&] {
            const auto view = pd::make_view(worst);
            const auto r = engine.detect_all(worst, pc::SegmentIndex{0}, *view);
            ok &= r.has_value();
        }));
    }
    row("128 windows, worst job (ms)", worst_ms);
    std::vector<double> cold_ms;
    for (int rep = 0; rep < 3; ++rep) {
        cold_ms.push_back(time_ms([&] { (void)pn::NerEngine::make(model_dir); }));
    }
    row("cold start: read, verify, session (ms)", cold_ms);

    // 4. 부하(worker 2개, 대기열 16, 대기 상한 10초).
    std::printf("\n");
    const auto steady = run_load(*pool, texts256, 8, 25);
    print_load("8 callers x 25, 256 tokens (ms)", steady);
    std::printf("%-46s %10.1f\n", "throughput (requests/s)", 1000.0 * static_cast<double>(steady.ok) / steady.wall_ms);
    ok &= report("steady load errors (count)", static_cast<double>(steady.overloaded + steady.timeout + steady.other), 0.0);
    const auto burst = run_load(*pool, texts256, 32, 1);
    print_load("32 callers at once, 256 tokens (ms)", burst);
    ok &= report("burst unexpected errors (count)", static_cast<double>(burst.other), 0.0);
    const auto worst_burst = run_load(*pool, {worst}, 8, 1);
    print_load("8 worst jobs at once (ms)", worst_burst);
    std::printf("%-46s %10.1f  (참고: 대기 상한 %lld ms)\n", "worst job wait max (ms)",
                worst_burst.ms.empty() ? 0.0 : *std::ranges::max_element(worst_burst.ms),
                static_cast<long long>(pn::ner_wait_limit.count()));

#ifdef PA_MEASURE_WITH_VAULT
    // 5. 잔여 검사: 실제 Vault 로 보호한 뒤 다시 탐지.
    prompt_airlock::vault_client::ServiceOptions o;
    o.exe = PA_VAULT_EXE;
    prompt_airlock::vault_client::VaultService service(o);
    const auto detectors = *pd::Detectors::make({}, pool);
    std::size_t rejected = 0, leaked = 0, policy_blocked = 0;
    std::vector<std::string> rejected_ids;
    for (int run = 0; run < residual_runs; ++run) {
        for (const auto& r : records) {
            const auto result = protect(detectors, service, r.text);
            if (result.policy_blocked) {
                ++policy_blocked;
            } else if (!result.verified) {
                ++rejected;
                rejected_ids.push_back(r.id + "(" + r.variant + ")");
                if (explain) {
                    std::printf("REJECT %s %s => %s | %s\n", r.id.c_str(), r.text.c_str(), result.sent.c_str(),
                                result.why.c_str());
                }
            }
            for (const auto& g : r.gold) {
                leaked += run == 0 && result.sent.find(g.text) != std::string::npos;
            }
        }
    }
    std::printf("\nresidual runs: %d (requests %zu)\n", residual_runs, records.size() * static_cast<std::size_t>(residual_runs));
    ok &= report("residual check rejections (count)", static_cast<double>(rejected), 0.0);
    std::printf("%-46s %10zu  (참고, 차단 종류가 있어 보호 전에 막힘)\n", "blocked by policy before protection", policy_blocked);
    std::printf("%-46s %10zu  (참고, 재현율에서 놓친 이름이 그대로 나간 수)\n", "gold names left in sent text", leaked);
    if (!rejected_ids.empty()) {
        std::printf("rejected: ");
        for (const auto& id : rejected_ids) {
            std::printf("%s ", id.c_str());
        }
        std::printf("\n");
    }
#else
    std::printf("\nresidual check: skipped (PA_WITH_VAULT=OFF)\n");
#endif
    return ok ? 0 : 1;
}
