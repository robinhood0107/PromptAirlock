#include "decode.hpp"

#include <algorithm>

namespace prompt_airlock::ner {
namespace {

bool is_space_or_zero_width(char32_t c) {
  return c == U' ' || c == U'\t' || c == U'\n' || c == U'\r' || c == 0x3000 || c == 0xA0 ||
         (c >= 0x2000 && c <= 0x200A) || is_zero_width(c);
}

// 원문 span 의 앞뒤 공백·zero-width 문자를 걷어낸다(Metaspace 토큰이 앞 공백을 포함하기 때문).
ByteSpan trim(std::string_view original, ByteSpan s) {
  auto b = s.begin.value, e = s.end.value;
  while (b < e) {
    std::size_t len = 1;
    const auto lead = static_cast<unsigned char>(original[b]);
    if (lead >= 0xF0) len = 4; else if (lead >= 0xE0) len = 3; else if (lead >= 0xC0) len = 2;
    auto one = decode_utf8(original.substr(b, len));
    if (!one || one->empty() || !is_space_or_zero_width(one->front().cp)) break;
    b += len;
  }
  while (e > b) {
    std::size_t s0 = e - 1;
    while (s0 > b && (static_cast<unsigned char>(original[s0]) & 0xC0) == 0x80) --s0;
    auto one = decode_utf8(original.substr(s0, e - s0));
    if (!one || one->empty() || !is_space_or_zero_width(one->front().cp)) break;
    e = s0;
  }
  return ByteSpan{Utf8ByteOffset{b}, Utf8ByteOffset{e}};
}

struct Open {
  EntityType type;
  std::string subtype;
  ByteSpan bytes;
  bool closed = false;
};

bool has_batchim(char32_t c) { return is_hangul_syllable(c) && (c - 0xAC00) % 28 != 0; }
bool has_rieul_batchim(char32_t c) { return is_hangul_syllable(c) && (c - 0xAC00) % 28 == 8; }

enum class Cond { Any, NeedBatchim, NoBatchim, NoBatchimOrRieul, BatchimNotRieul };
struct Particle {
  std::u32string text;
  Cond cond;
  std::size_t min_remain;  // 잘라낸 뒤 남아야 하는 최소 음절(문자) 수
};

const std::vector<Particle>& particles() {
  static const std::vector<Particle> table = {
      {U"에게서", Cond::Any, 2}, {U"에게", Cond::Any, 2}, {U"께서", Cond::Any, 2}, {U"한테", Cond::Any, 2},
      {U"에서", Cond::Any, 2},   {U"까지", Cond::Any, 2}, {U"부터", Cond::Any, 2}, {U"처럼", Cond::Any, 2},
      {U"보다", Cond::Any, 2},   {U"이랑", Cond::NeedBatchim, 2}, {U"으로", Cond::BatchimNotRieul, 2},
      {U"은", Cond::NeedBatchim, 2}, {U"는", Cond::NoBatchim, 2}, {U"이", Cond::NeedBatchim, 2},
      {U"가", Cond::NoBatchim, 2},   {U"을", Cond::NeedBatchim, 2}, {U"를", Cond::NoBatchim, 2},
      {U"과", Cond::NeedBatchim, 2}, {U"와", Cond::NoBatchim, 2},   {U"랑", Cond::NoBatchim, 2},
      {U"로", Cond::NoBatchimOrRieul, 2},
      // 짝이 없는 한 음절 조사는 이름 음절(김현도 등)과 겹치므로 더 긴 잔여를 요구한다.
      {U"의", Cond::Any, 3}, {U"도", Cond::Any, 3}, {U"만", Cond::Any, 3},
      // 호칭
      {U"님", Cond::Any, 2}, {U"씨", Cond::Any, 2},
  };
  return table;
}

bool cond_ok(Cond c, char32_t prev) {
  switch (c) {
    case Cond::Any: return true;
    case Cond::NeedBatchim: return has_batchim(prev);
    case Cond::NoBatchim: return is_hangul_syllable(prev) && !has_batchim(prev);
    case Cond::NoBatchimOrRieul: return is_hangul_syllable(prev) && (!has_batchim(prev) || has_rieul_batchim(prev));
    case Cond::BatchimNotRieul: return has_batchim(prev) && !has_rieul_batchim(prev);
  }
  return false;
}

}  // namespace

std::vector<LabelInfo> build_label_table(const std::vector<std::string>& id2label,
                                         const std::map<std::string, EntityType>& entity_map) {
  std::vector<LabelInfo> out;
  out.reserve(id2label.size());
  for (const auto& label : id2label) {
    LabelInfo info;
    std::string name;
    if (label.size() > 2 && label[1] == '-' && std::string_view("BIES").find(label[0]) != std::string_view::npos) {
      info.prefix = label[0];
      name = label.substr(2);
    } else if (label.size() > 2 && label[label.size() - 2] == '-' &&
               std::string_view("BIES").find(label.back()) != std::string_view::npos) {
      info.prefix = label.back();
      name = label.substr(0, label.size() - 2);
    }
    if (const auto it = entity_map.find(name); !name.empty() && it != entity_map.end()) {
      info.type = it->second;
      info.subtype = name;
    } else {
      info.prefix = 'O';
    }
    out.push_back(std::move(info));
  }
  return out;
}

std::vector<EntitySpan> decode_entities(std::span<const Token> tokens, const Logits& logits,
                                        std::span<const LabelInfo> labels, std::string_view original,
                                        DecodeOptions opts) {
  std::vector<Open> spans;
  for (std::size_t i = 0; i < tokens.size(); ++i) {
    const auto& t = tokens[i];
    if (t.special || t.src.empty()) continue;
    const auto& info = labels[logits.argmax(i)];
    if (!info.type) {
      if (!spans.empty()) spans.back().closed = true;
      continue;
    }
    const bool continues = !spans.empty() && !spans.back().closed && spans.back().type == *info.type &&
                           spans.back().subtype == info.subtype && (info.prefix == 'I' || info.prefix == 'E');
    // 같은 원문 문자를 공유하는 byte-fallback 토큰은 이전 span 을 늘리기만 한다.
    const bool same_char = !spans.empty() && t.src.begin < spans.back().bytes.end;
    if (continues || (same_char && spans.back().type == *info.type)) {
      spans.back().bytes.end = std::max(spans.back().bytes.end, t.src.end);
    } else {
      spans.push_back(Open{*info.type, info.subtype, t.src});
    }
    if (info.prefix == 'E' || info.prefix == 'S') spans.back().closed = true;
  }

  if (opts.merge_adjacent) {
    std::vector<Open> merged;
    for (auto& s : spans) {
      if (!merged.empty()) {
        auto& p = merged.back();
        const auto gap = original.substr(p.bytes.end.value, s.bytes.begin.value - std::min(s.bytes.begin.value, p.bytes.end.value));
        const bool blank = std::all_of(gap.begin(), gap.end(), [](char c) { return c == ' '; });
        const bool person_parts = p.type == EntityType::Person && s.type == EntityType::Person &&
                                  p.subtype != s.subtype && blank;
        // 같은 type 이 구분자 없이 맞닿으면(간격 0 바이트) 한 entity 로 본다.
        const bool touching = p.type == s.type && p.bytes.end == s.bytes.begin;
        if ((person_parts || touching) && p.bytes.end <= s.bytes.begin) {
          p.bytes.end = s.bytes.end;
          p.subtype = "MERGED";
          continue;
        }
      }
      merged.push_back(s);
    }
    spans = std::move(merged);
  }

  std::vector<EntitySpan> out;
  for (const auto& s : spans) {
    const auto b = trim(original, s.bytes);
    if (!b.empty()) out.push_back(EntitySpan{s.type, b});
  }
  return out;
}

std::vector<EntitySpan> strip_trailing_particles(std::span<const EntitySpan> spans,
                                                 std::span<const Unit> normalized) {
  std::vector<EntitySpan> out;
  for (auto span : spans) {
    for (int round = 0; round < 2; ++round) {
      // span 안에 완전히 들어가는 정규화 unit 들
      std::vector<std::size_t> idx;
      for (std::size_t k = 0; k < normalized.size(); ++k)
        if (normalized[k].src.begin >= span.bytes.begin && normalized[k].src.end <= span.bytes.end) idx.push_back(k);
      bool changed = false;
      for (const auto& p : particles()) {
        const auto n = p.text.size();
        if (idx.size() < n + p.min_remain) continue;
        bool match = true;
        for (std::size_t k = 0; k < n; ++k)
          match = match && normalized[idx[idx.size() - n + k]].cp == p.text[k];
        if (!match) continue;
        const auto& prev = normalized[idx[idx.size() - n - 1]];
        if (!cond_ok(p.cond, prev.cp)) continue;
        span.bytes.end = normalized[idx[idx.size() - n]].src.begin;
        changed = true;
        break;
      }
      if (!changed) break;
    }
    out.push_back(span);
  }
  return out;
}

std::string_view to_string(EntityType t) { return t == EntityType::Person ? "PERSON" : "ORG"; }

}  // namespace prompt_airlock::ner
