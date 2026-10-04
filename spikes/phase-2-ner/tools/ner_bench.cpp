// 후보 하나를 한 프로세스에서 측정한다(peak working set 이 후보별로 분리되도록).
// 사용: ner_bench <candidate> <model_root> <fixtures.jsonl> [runs] [nfc|nfkc]  |  ... dump <fixture-id>
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "eval.hpp"

using namespace prompt_airlock::ner;
using Clock = std::chrono::steady_clock;

namespace {

double ms_since(Clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

struct Mem {
  double working_mb, peak_mb;
};
Mem memory() {
  PROCESS_MEMORY_COUNTERS pmc{};
  GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof pmc);
  return {pmc.WorkingSetSize / 1048576.0, pmc.PeakWorkingSetSize / 1048576.0};
}

double percentile(std::vector<double> v, double p) {
  std::sort(v.begin(), v.end());
  const auto idx = static_cast<std::size_t>(p * static_cast<double>(v.size() - 1) + 0.5);
  return v[std::min(idx, v.size() - 1)];
}

std::size_t token_count(Pipeline& p, const std::string& text) {
  auto n = normalize(text, p.norm_policy());
  return n ? p.tokenizer().encode(*n).size() : 0;
}

// 반복 문단에서 공백 경계로 잘라 토큰 수가 target 이하인 가장 긴 접두를 만든다.
std::string build_long_prompt(Pipeline& p, const std::string& paragraph, std::size_t target) {
  std::string pool;
  while (token_count(p, pool) < target + 32) pool += (pool.empty() ? "" : " ") + paragraph;
  std::string best;
  std::size_t pos = 0;
  while (true) {
    const auto next = pool.find(' ', pos + 1);
    const auto cand = pool.substr(0, next == std::string::npos ? pool.size() : next);
    if (token_count(p, cand) > target) break;
    best = cand;
    if (next == std::string::npos) break;
    pos = next;
  }
  return best;
}

nlohmann::json latency(Pipeline& p, const std::string& text, int runs) {
  for (int i = 0; i < 10; ++i) (void)p.analyze(text);  // warm-up
  std::vector<double> t;
  t.reserve(static_cast<std::size_t>(runs));
  for (int i = 0; i < runs; ++i) {
    const auto t0 = Clock::now();
    auto a = p.analyze(text);
    t.push_back(ms_since(t0));
    if (!a) return {{"error", std::string(to_string(a.error()))}};
  }
  double sum = 0;
  for (double x : t) sum += x;
  return {{"tokens", token_count(p, text)},
          {"bytes", text.size()},
          {"runs", runs},
          {"p50_ms", percentile(t, 0.5)},
          {"p95_ms", percentile(t, 0.95)},
          {"max_ms", percentile(t, 1.0)},
          {"mean_ms", sum / static_cast<double>(t.size())}};
}

}  // namespace

int main(int argc, char** argv) {
  SetConsoleOutputCP(CP_UTF8);
  if (argc < 4) {
    std::cerr << "usage: ner_bench <candidate> <model_root> <fixtures.jsonl> [runs] [nfc|nfkc]\n"
                 "       ner_bench <candidate> <model_root> <fixtures.jsonl> dump <fixture-id>\n";
    return 2;
  }
  const auto* cand = find_candidate(argv[1]);
  if (!cand) { std::cerr << "unknown candidate\n"; return 2; }
  const std::filesystem::path root = argv[2];
  auto fixtures = load_fixtures(argv[3]);
  if (!fixtures) { std::cerr << fixtures.error() << "\n"; return 1; }
  if (argc > 5 && std::string(argv[4]) == "dump") {
    // 진단: 지정 fixture 의 토큰별 label 을 출력한다.
    Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "pa-phase2");
    auto pipe = Pipeline::load(env, *cand, root);
    if (!pipe) { std::cerr << pipe.error() << "\n"; return 1; }
    for (const auto& f : *fixtures) {
      if (f.id != argv[5]) continue;
      auto a = pipe->analyze(f.text);
      if (!a) return 1;
      for (std::size_t i = 0; i < a->tokens.size(); ++i) {
        const auto& t = a->tokens[i];
        std::cout << i << "\t" << t.id << "\t" << pipe->tokenizer().piece(t.id) << "\t["
                  << f.text.substr(t.src.begin.value, t.src.size()) << "]\t" << t.src.begin.value << "-"
                  << t.src.end.value << "\t" << pipe->id2label()[a->label_ids[i]] << "\n";
      }
    }
    return 0;
  }
  const int runs = argc > 4 ? std::stoi(argv[4]) : 200;
  const std::string norm_mode = argc > 5 ? argv[5] : "nfc";
  NormPolicy policy{};
  policy.compat = norm_mode == "nfkc";

  nlohmann::json out;
  out["candidate"] = cand->name;
  out["repo"] = cand->repo;
  out["commit"] = cand->commit;
  out["norm"] = norm_mode;
  out["onnx_bytes"] = std::filesystem::file_size(root / cand->onnx);
  out["ort_version"] = Ort::GetVersionString();
  out["mem_start"] = {{"working_mb", memory().working_mb}};

  // cold start: tokenizer 로드 + 세션 생성 + 첫 추론
  const auto t_load = Clock::now();
  Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "pa-phase2");
  const auto t_pipe = Clock::now();
  auto pipe = Pipeline::load(env, *cand, root, policy);
  const double load_ms = ms_since(t_pipe);
  if (!pipe) { std::cerr << pipe.error() << "\n"; return 1; }
  const std::string short_text = "김민수는 누리별테크에 다닌다.";
  const auto t_first = Clock::now();
  auto first = pipe->analyze(short_text);
  const double first_ms = ms_since(t_first);
  if (!first) { std::cerr << "first run failed\n"; return 1; }
  out["cold"] = {{"tokenizer_load_ms", pipe->load_timings().tokenizer_ms},
                 {"session_create_ms", pipe->load_timings().session_ms},
                 {"pipeline_load_ms", load_ms},
                 {"first_run_ms", first_ms},
                 {"cold_start_ms", load_ms + first_ms},
                 {"since_process_section_ms", ms_since(t_load)}};
  out["model_inputs"] = pipe->model().input_names();
  out["tokenizer_kind"] = std::string(pipe->tokenizer().kind());
  out["mem_after_load"] = {{"working_mb", memory().working_mb}};

  // fixture 채점
  Score raw_total, post_total;
  OffsetReport off_total;
  std::size_t failed = 0;
  nlohmann::json per_fixture = nlohmann::json::array();
  auto add = [](Score& t, const Score& s) {
    t.person.tp += s.person.tp; t.person.fp += s.person.fp; t.person.fn += s.person.fn;
    t.org.tp += s.org.tp; t.org.fp += s.org.fp; t.org.fn += s.org.fn;
    t.particle_errors += s.particle_errors; t.other_boundary += s.other_boundary;
    t.misses.insert(t.misses.end(), s.misses.begin(), s.misses.end());
  };
  for (const auto& f : *fixtures) {
    auto a = pipe->analyze(f.text);
    if (!a) { ++failed; continue; }
    const auto off = verify_offsets(f.text, *a, pipe->tokenizer(), policy);
    off_total.tokens_checked += off.tokens_checked;
    off_total.token_errors += off.token_errors;
    off_total.entity_errors += off.entity_errors;
    for (const auto& d : off.details) off_total.details.push_back(f.id + ": " + d);
    const auto rs = score(f, a->raw);
    const auto ps = score(f, a->post);
    add(raw_total, rs);
    add(post_total, ps);
    nlohmann::json preds = nlohmann::json::array();
    for (const auto& e : a->raw)
      preds.push_back({to_string(e.type), e.bytes.begin.value, e.bytes.end.value,
                       f.text.substr(e.bytes.begin.value, e.bytes.size()),
                       to_codepoint_offset(f.text, e.bytes.begin).value, to_codepoint_offset(f.text, e.bytes.end).value});
    per_fixture.push_back({{"id", f.id}, {"tokens", a->tokens.size()}, {"raw", preds}});
  }
  auto summarize = [](const Score& s) {
    auto pr = [](const TypeCounts& c) {
      const double p = c.tp + c.fp ? double(c.tp) / double(c.tp + c.fp) : 0.0;
      const double r = c.tp + c.fn ? double(c.tp) / double(c.tp + c.fn) : 0.0;
      return nlohmann::json{{"tp", c.tp}, {"fp", c.fp}, {"fn", c.fn}, {"precision", p}, {"recall", r}};
    };
    return nlohmann::json{{"person", pr(s.person)}, {"org", pr(s.org)}, {"particle_boundary_errors", s.particle_errors},
                          {"other_boundary_errors", s.other_boundary}, {"misses", s.misses}};
  };
  out["fixtures"] = fixtures->size();
  out["pipeline_failures"] = failed;
  out["score_raw"] = summarize(raw_total);
  out["score_post"] = summarize(post_total);
  out["offsets"] = {{"tokens_checked", off_total.tokens_checked},
                    {"token_errors", off_total.token_errors},
                    {"entity_errors", off_total.entity_errors},
                    {"details", off_total.details}};
  out["predictions"] = per_fixture;

  // 지연시간: 짧은 프롬프트, 256 토큰 프롬프트
  std::string paragraph;
  for (const auto& f : *fixtures)
    if (f.id == "long-01") paragraph = f.text;
  const auto long_text = build_long_prompt(*pipe, paragraph, 256);
  out["latency_short"] = latency(*pipe, short_text, runs);
  out["latency_256"] = latency(*pipe, long_text, runs);
  // 512 토큰 한도 초과 입력은 잘리지 않고 거부되어야 한다.
  std::string too_long = long_text;
  while (token_count(*pipe, too_long) <= cand->max_tokens) too_long += " " + paragraph;
  auto rejected = pipe->analyze(too_long);
  out["over_limit_rejected"] = !rejected && rejected.error() == PipelineError::InputTooLong;

  const auto m = memory();
  out["mem_end"] = {{"working_mb", m.working_mb}, {"peak_working_set_mb", m.peak_mb}};
  std::cout << out.dump(2) << "\n";
  return 0;
}
