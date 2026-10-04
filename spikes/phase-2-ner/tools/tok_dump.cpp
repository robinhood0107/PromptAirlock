// fixture 마다 native tokenizer 결과(id, 원문 바이트 구간)를 JSONL 로 출력한다.
// oracle(transformers.js, 개발 전용)과 비교할 입력을 만든다.
// 사용: tok_dump <tokenizer.json> <fixtures.jsonl> <nfc|raw>
#include <cstdio>
#include <iostream>
#include <string>

#include <nlohmann/json.hpp>

#include "fixtures.hpp"
#include "tokenizer.hpp"

using namespace prompt_airlock::ner;

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "usage: tok_dump <tokenizer.json> <fixtures.jsonl> <nfc|raw>\n";
    return 2;
  }
  auto tok = load_tokenizer(argv[1]);
  if (!tok) { std::cerr << "tokenizer: " << to_string(tok.error()) << "\n"; return 1; }
  auto fixtures = load_fixtures(argv[2]);
  if (!fixtures) { std::cerr << fixtures.error() << "\n"; return 1; }
  const std::string mode = argv[3];
  const NormPolicy policy = mode == "raw" ? NormPolicy{false, false} : NormPolicy{};
  for (const auto& f : *fixtures) {
    auto norm = normalize(f.text, policy);
    if (!norm) { std::cerr << f.id << ": normalize failed\n"; return 1; }
    const auto tokens = (*tok)->encode(*norm);
    nlohmann::json j;
    j["id"] = f.id;
    j["mode"] = mode;
    j["norm_text"] = to_utf8(*norm);
    auto& ids = j["ids"] = nlohmann::json::array();
    auto& spans = j["spans"] = nlohmann::json::array();
    for (const auto& t : tokens) {
      ids.push_back(t.id);
      spans.push_back({t.src.begin.value, t.src.end.value});
    }
    std::cout << j.dump() << "\n";
  }
  return 0;
}
