#include "eval.hpp"

#include <algorithm>

namespace prompt_airlock::ner {
namespace {

std::string slice(std::string_view s, ByteSpan b) { return std::string(s.substr(b.begin.value, b.size())); }

std::string replace_all(std::string s, std::string_view from, std::string_view to) {
  for (std::size_t p = s.find(from); p != std::string::npos; p = s.find(from, p + to.size()))
    s.replace(p, from.size(), to);
  return s;
}

bool span_ok(std::string_view original, ByteSpan b) {
  return b.begin < b.end && b.end.value <= original.size() && is_codepoint_boundary(original, b.begin) &&
         is_codepoint_boundary(original, b.end);
}

}  // namespace

OffsetReport verify_offsets(std::string_view original, const Analysis& a, const Tokenizer& tok, NormPolicy policy) {
  OffsetReport r;
  Utf8ByteOffset prev{0};
  for (const auto& t : a.tokens) {
    if (t.special) continue;
    ++r.tokens_checked;
    // Metaspace 가 앞에 붙인 단독 ▁ 는 원문 바이트가 없는 합성 토큰이다(빈 구간이 정상).
    if (t.src.empty() && tok.kind() != "wordpiece" && tok.piece(t.id) == "▁" &&
        is_codepoint_boundary(original, t.src.begin) && t.src.begin >= prev)
      continue;
    if (!span_ok(original, t.src) || t.src.begin < prev) {
      ++r.token_errors;
      r.details.push_back("token span invalid id=" + std::to_string(t.id));
      continue;
    }
    prev = t.src.begin;
    if (t.id == tok.unk_id() || tok.is_byte_fallback(t.id)) continue;  // 문자열 비교 불가, 경계만 확인
    auto norm = normalize(original.substr(t.src.begin.value, t.src.size()), policy);
    if (!norm) { ++r.token_errors; r.details.push_back("token slice not normalizable"); continue; }
    const auto got = to_utf8(*norm);
    std::string want(tok.piece(t.id));
    if (tok.kind() == "wordpiece") {
      if (want.starts_with("##")) want.erase(0, 2);
    } else {
      want = replace_all(want, "▁", " ");
      if (want.starts_with(' ') && !got.starts_with(' ')) want.erase(0, 1);  // Metaspace 가 앞에 붙인 ▁
    }
    if (got != want) {
      ++r.token_errors;
      r.details.push_back("token text mismatch want=[" + want + "] got=[" + got + "]");
    }
  }
  for (const auto* list : {&a.raw, &a.post}) {
    for (const auto& e : *list) {
      const bool ok = span_ok(original, e.bytes) && original[e.bytes.begin.value] != ' ' &&
                      original[e.bytes.end.value - 1] != ' ';
      if (!ok) { ++r.entity_errors; r.details.push_back("entity span invalid"); }
    }
  }
  return r;
}

Score score(const Fixture& f, std::span<const EntitySpan> preds) {
  Score s;
  std::vector<bool> used(preds.size(), false);
  auto counts = [&](EntityType t) -> TypeCounts& { return t == EntityType::Person ? s.person : s.org; };
  for (const auto& g : f.entities) {
    bool hit = false;
    for (std::size_t i = 0; i < preds.size(); ++i) {
      if (!used[i] && preds[i].type == g.type && preds[i].bytes == g.bytes) { used[i] = true; hit = true; break; }
    }
    if (hit) { ++counts(g.type).tp; continue; }
    ++counts(g.type).fn;
    // 왜 놓쳤는지 분류한다.
    std::string why = "miss";
    for (std::size_t i = 0; i < preds.size(); ++i) {
      const auto& p = preds[i];
      if (used[i] || p.type != g.type || p.bytes.end <= g.bytes.begin || p.bytes.begin >= g.bytes.end) continue;
      const auto extra = decode_utf8(std::string_view(f.text).substr(
          g.bytes.end.value, p.bytes.end.value > g.bytes.end.value ? p.bytes.end.value - g.bytes.end.value : 0));
      const bool hangul_tail = p.bytes.begin == g.bytes.begin && p.bytes.end > g.bytes.end && extra &&
                               std::all_of(extra->begin(), extra->end(), [](const Unit& u) {
                                 return is_hangul_syllable(u.cp) || (u.cp >= 0x1100 && u.cp <= 0x11FF);
                               });
      if (hangul_tail) { ++s.particle_errors; why = "particle"; } else { ++s.other_boundary; why = "boundary"; }
      break;
    }
    s.misses.push_back(f.id + " " + std::string(to_string(g.type)) + " [" + g.text + "] " + why);
  }
  for (std::size_t i = 0; i < preds.size(); ++i) {
    if (used[i]) continue;
    ++counts(preds[i].type).fp;
    s.misses.push_back(f.id + " FP " + std::string(to_string(preds[i].type)) + " [" +
                       slice(f.text, preds[i].bytes) + "]");
  }
  return s;
}

}  // namespace prompt_airlock::ner
