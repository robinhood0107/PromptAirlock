// 결정론 탐지 측정(Phase 5 계획 6절, 결정 #61 기준). 기본 빌드·ctest 에 넣지 않고 직접 실행한다.
//   cmake --build <빌드 디렉터리> --target detect_measure && <빌드 디렉터리>/tests/measure/detect_measure
// 합성 업무 문서(고정 seed)로 잘못 차단하는 비율, 합성 양성 재현율, 4 KiB·64 KiB 처리 시간, 최악 입력 시간 비율을 잰다.
// 원문은 출력하지 않는다. 기준을 하나라도 넘지 못하면 종료 코드 1.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "prng.hpp"
#include "prompt_airlock/detect/detectors.hpp"

namespace pc = prompt_airlock::core;
namespace pd = prompt_airlock::detect;
using pc::EntityType;

namespace {

constexpr std::uint64_t seed = 20261018;
constexpr std::size_t negative_documents = 2000;

// 개인 정보가 없는 업무 문장 틀. {n} 은 숫자, {h} 는 16진수, {w} 는 영문 단어로 채운다.
const std::vector<std::string_view> templates = {
    "주문번호 {n} 의 배송 상태를 확인해 주세요.",
    "결재 문서 {n} 번을 다음 주까지 검토해 주세요.",
    "이번 달 예산은 {n}원이고 집행률은 {n}% 입니다.",
    "회의는 2026-10-{d} {t} 에 3층 회의실에서 합니다.",
    "배포 버전은 v{d}.{d}.{d} 이고 빌드 번호는 {n} 입니다.",
    "커밋 해시 {h} 를 기준으로 다시 빌드해 주세요.",
    "요청 번호 REQ-2026-{n} 처리 결과를 공유합니다.",
    "재고 수량은 {n}개이며 창고 코드는 WH{d} 입니다.",
    "고객님, 시스템 점검으로 {t} 부터 서비스가 중단됩니다.",
    "고객님 병원 예약 시스템 점검 안내입니다.",
    "당뇨의 초기 증상을 일반적인 수준에서 설명해 주세요.",
    "종교와 문화의 관계를 다룬 보고서를 요약해 주세요.",
    "서버 장애 원인을 분석하고 재발 방지 대책을 써 주세요.",
    "Please summarize the {w} report and list action items.",
    "The meeting about {w} is scheduled for {t}.",
    "for (int i = 0; i < {n}; ++i) {{ total += values[i]; }}",
    "https://example.invalid/docs/{w}?page={d} 문서를 참고하세요.",
    "로그인 화면 문구를 쉽게 고쳐 주세요.",
    "비밀번호 정책 문서를 요약해 주세요.",
    "계좌 이체 수수료 정책을 정리해 주세요.",
    "입금 확인은 영업일 기준 2일이 걸립니다.",
    "전화 문의는 평일 {t} 까지 받습니다.",
    "통계표의 {n} 행부터 {n} 행까지 합계를 구해 주세요.",
    "프로젝트 코드 PRJ{n} 의 일정표를 갱신해 주세요.",
};
const std::vector<std::string_view> words = {"quarterly", "budget", "migration", "security", "inventory",
                                             "roadmap", "incident", "procurement", "training", "audit"};

std::string fill(std::string_view t, pa_test::SplitMix64& rng) {
    std::string out;
    for (std::size_t i = 0; i < t.size(); ++i) {
        if (t[i] == '{' && i + 2 < t.size() && t[i + 2] == '}') {
            const char k = t[i + 1];
            if (k == 'n') {
                const auto digits = 1 + rng.below(14);
                for (std::uint64_t j = 0; j < digits; ++j) {
                    out.push_back(static_cast<char>('0' + rng.below(10)));
                }
            } else if (k == 'd') {
                out += std::to_string(1 + rng.below(28));
            } else if (k == 't') {
                out += std::to_string(9 + rng.below(9)) + ":" + std::to_string(10 + rng.below(50));
            } else if (k == 'h') {
                for (int j = 0; j < 40; ++j) {
                    out.push_back("0123456789abcdef"[rng.below(16)]);
                }
            } else if (k == 'w') {
                out += words[rng.below(words.size())];
            }
            i += 2;
        } else if (t[i] == '{' && i + 1 < t.size() && t[i + 1] == '{') {
            out.push_back('{');
            ++i;
        } else if (t[i] == '}' && i + 1 < t.size() && t[i + 1] == '}') {
            out.push_back('}');
            ++i;
        } else {
            out.push_back(t[i]);
        }
    }
    return out;
}

std::string document_text(pa_test::SplitMix64& rng, std::size_t bytes) {
    std::string out;
    while (out.size() < bytes) {
        out += fill(templates[rng.below(templates.size())], rng);
        out += rng.chance(1, 4) ? "\n" : " ";
    }
    // 글자 중간에서 자르지 않도록 마지막 줄바꿈·공백에서 자른다.
    const auto cut = out.find_last_of(" \n", bytes);
    out.resize(cut == std::string::npos ? bytes : cut);
    return out;
}

pc::PromptDocument make_document(std::string_view text) {
    std::vector<pc::SensitiveText> parts;
    parts.push_back(pc::SensitiveText::copy_of(text));
    pc::PromptDocumentBuilder builder;
    builder.add_message(pc::MessageRole::User, pc::ContentForm::String, std::move(parts));
    return *std::move(builder).build();
}

std::size_t detect_failures = 0;

// 탐지 실패도 요청 거절이므로 따로 센다.
pc::EntityTypeSet types_of(const pd::Detectors& d, std::string_view text) {
    pc::EntityTypeSet types;
    const auto result = d.detect(make_document(text));
    if (!result) {
        ++detect_failures;
        return types;
    }
    for (const auto& e : result->entities) {
        types.insert(e.type());
    }
    return types;
}

double percentile(std::vector<double> v, double p) {
    std::ranges::sort(v);
    return v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))];
}

double time_ms(const pd::Detectors& d, const pc::PromptDocument& document) {
    const auto start = std::chrono::steady_clock::now();
    const auto result = d.detect(document);
    const auto end = std::chrono::steady_clock::now();
    if (!result) {
        std::puts("detect failed during timing");
    }
    return std::chrono::duration<double, std::milli>(end - start).count();
}

std::vector<double> timings(const pd::Detectors& d, std::size_t bytes, std::size_t runs, pa_test::SplitMix64& rng) {
    std::vector<double> out;
    for (std::size_t i = 0; i < runs; ++i) {
        const auto document = make_document(document_text(rng, bytes));
        out.push_back(time_ms(d, document));
    }
    return out;
}

std::string repeat(std::string_view unit, std::size_t bytes) {
    std::string out;
    while (out.size() + unit.size() <= bytes) {
        out += unit;
    }
    return out;
}

bool report(const char* name, double value, double limit, bool upper = true) {
    const bool ok = upper ? value <= limit : value >= limit;
    std::printf("%-44s %10.3f  %s %8.3f  %s\n", name, value, upper ? "<=" : ">=", limit, ok ? "PASS" : "FAIL");
    return ok;
}

}  // namespace

int main() {
    const auto detectors = *pd::Detectors::make({});
    pa_test::SplitMix64 rng(seed);
    bool ok = true;

    // 1. 잘못 차단하는 비율: 개인 정보 없는 합성 문서(문서당 4~12문장)에서 종류별로 차단된 문서 비율.
    std::size_t bank = 0, credential = 0, sensitive = 0, any_block = 0;
    for (std::size_t i = 0; i < negative_documents; ++i) {
        std::string text;
        const auto sentences = 4 + rng.below(9);
        for (std::uint64_t s = 0; s < sentences; ++s) {
            text += fill(templates[rng.below(templates.size())], rng) + " ";
        }
        const auto types = types_of(detectors, text);
        bank += types.contains(EntityType::BankAccount);
        credential += types.contains(EntityType::Credential);
        sensitive += types.contains(EntityType::SensitivePersonalInfo);
        bool blocked = false;
        types.for_each([&](EntityType t) { blocked = blocked || pc::default_action(t) == pc::Action::Block; });
        any_block += blocked;
    }
    const auto rate = [](std::size_t n) { return 100.0 * static_cast<double>(n) / negative_documents; };
    std::printf("negative documents: %zu (seed %llu)\n", negative_documents, static_cast<unsigned long long>(seed));
    ok &= report("false block rate BankAccount (%)", rate(bank), 5.0);
    ok &= report("false block rate Credential (%)", rate(credential), 2.0);
    ok &= report("false block rate SensitivePersonalInfo (%)", rate(sensitive), 5.0);
    std::printf("%-44s %10.3f  (참고, 기준 없음)\n", "any blocked type (%)", rate(any_block));
    ok &= report("detect failures (count)", static_cast<double>(detect_failures), 0.0);

    // 2. 합성 양성 재현율.
    const std::vector<std::pair<std::string_view, EntityType>> positives = {
        {"주민번호 900101-1234567", EntityType::KoreanRrn},
        {"입금 계좌 1234567890", EntityType::BankAccount},
        {"IBAN DE00 7777 7777 7777 7777 77", EntityType::BankAccount},
        {"비밀번호: Qwer1234", EntityType::Credential},
        {"김가상 과장은 당뇨 치료 중입니다.", EntityType::SensitivePersonalInfo},
        {"카드 4111 1111 1111 1111", EntityType::CardNumber},
        {"여권 M123A4567", EntityType::KoreanPassportNo},
        {"키 AKIA0000AAAA1111BBBB", EntityType::ApiKey},
    };
    std::size_t found = 0;
    for (const auto& [text, type] : positives) {
        found += types_of(detectors, text).contains(type);
    }
    ok &= report("synthetic positive recall (%)", 100.0 * static_cast<double>(found) / positives.size(), 100.0, false);

    // 3. 처리 시간(이 빌드 설정, 단일 스레드).
    const auto small = timings(detectors, 4 * 1024, 200, rng);
    const auto large = timings(detectors, 64 * 1024 - 64, 50, rng);
    std::printf("%-44s %10.3f\n", "4 KiB p50 (ms)", percentile(small, 0.5));
    ok &= report("4 KiB p95 (ms)", percentile(small, 0.95), 5.0);
    std::printf("%-44s %10.3f\n", "64 KiB p50 (ms)", percentile(large, 0.5));
    ok &= report("64 KiB p95 (ms)", percentile(large, 0.95), 50.0);

    // 4. 최악 입력의 64 KiB / 4 KiB 시간 비율(선형이면 약 16).
    const std::vector<std::pair<const char*, std::string_view>> worst = {
        {"digits and hyphens", "1-"}, {"at signs", "a@"}, {"base64 alphabet", "QUJD"},
        {"account words and digits", "계좌 1 "}, {"percent escapes", "%41"}, {"hangul names", "김가상 과장 "},
    };
    for (const auto& [name, unit] : worst) {
        const auto t4 = time_ms(detectors, make_document(repeat(unit, 4 * 1024)));
        const auto t64 = time_ms(detectors, make_document(repeat(unit, 64 * 1024 - 64)));
        ok &= report((std::string("worst ratio ") + name).c_str(), t64 / std::max(t4, 0.001), 32.0);
    }
    return ok ? 0 : 1;
}
