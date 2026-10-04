#include "tokenizer.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <limits>
#include <string>
#include <unordered_map>

#include <nlohmann/json.hpp>
#include <utf8proc.h>

namespace prompt_airlock::ner {
namespace {

using json = nlohmann::json;

struct StringHash {
  using is_transparent = void;
  std::size_t operator()(std::string_view s) const { return std::hash<std::string_view>{}(s); }
};
using Vocab = std::unordered_map<std::string, std::int64_t, StringHash, std::equal_to<>>;

utf8proc_category_t category(char32_t cp) {
  return utf8proc_category(static_cast<utf8proc_int32_t>(cp));
}

// Unicode White_Space 속성(HF tokenizers 의 char::is_whitespace 와 같은 집합).
bool is_white_space(char32_t c) {
  return (c >= 0x09 && c <= 0x0D) || c == 0x20 || c == 0x85 || c == 0xA0 || c == 0x1680 ||
         (c >= 0x2000 && c <= 0x200A) || c == 0x2028 || c == 0x2029 || c == 0x202F ||
         c == 0x205F || c == 0x3000;
}

bool is_bert_control(char32_t c) {
  if (c == '\t' || c == '\n' || c == '\r') return false;
  switch (category(c)) {
    case UTF8PROC_CATEGORY_CC: case UTF8PROC_CATEGORY_CF: case UTF8PROC_CATEGORY_CO:
    case UTF8PROC_CATEGORY_CS: case UTF8PROC_CATEGORY_CN:
      return true;
    default:
      return false;
  }
}

bool is_bert_punct(char32_t c) {
  if ((c >= 33 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) || (c >= 123 && c <= 126))
    return true;
  switch (category(c)) {
    case UTF8PROC_CATEGORY_PC: case UTF8PROC_CATEGORY_PD: case UTF8PROC_CATEGORY_PS:
    case UTF8PROC_CATEGORY_PE: case UTF8PROC_CATEGORY_PI: case UTF8PROC_CATEGORY_PF:
    case UTF8PROC_CATEGORY_PO:
      return true;
    default:
      return false;
  }
}

bool is_cjk_ideograph(char32_t c) {
  return (c >= 0x4E00 && c <= 0x9FFF) || (c >= 0x3400 && c <= 0x4DBF) ||
         (c >= 0x20000 && c <= 0x2A6DF) || (c >= 0x2A700 && c <= 0x2B73F) ||
         (c >= 0x2B740 && c <= 0x2B81F) || (c >= 0x2B820 && c <= 0x2CEAF) ||
         (c >= 0xF900 && c <= 0xFAFF) || (c >= 0x2F800 && c <= 0x2FA1F);
}

std::vector<std::string> reverse(const Vocab& v) {
  std::int64_t max_id = -1;
  for (const auto& [k, id] : v) max_id = std::max(max_id, id);
  std::vector<std::string> r(static_cast<std::size_t>(max_id + 1));
  for (const auto& [k, id] : v) r[static_cast<std::size_t>(id)] = k;
  return r;
}

std::string_view piece_of(const std::vector<std::string>& r, std::int64_t id) {
  return id >= 0 && static_cast<std::size_t>(id) < r.size() ? std::string_view{r[static_cast<std::size_t>(id)]} : std::string_view{};
}

std::expected<std::int64_t, TokError> lookup(const Vocab& v, std::string_view s) {
  const auto it = v.find(s);
  if (it == v.end()) return std::unexpected(TokError::MissingToken);
  return it->second;
}

// TemplateProcessing 의 single 템플릿이 [special] A [special] 인지 확인하고 두 id 를 꺼낸다.
std::expected<std::pair<std::int64_t, std::int64_t>, TokError> wrap_ids(const json& post) {
  if (!post.is_object() || post.value("type", "") != "TemplateProcessing")
    return std::unexpected(TokError::Unsupported);
  const auto& single = post.at("single");
  if (single.size() != 3 || !single[0].contains("SpecialToken") || !single[1].contains("Sequence") ||
      !single[2].contains("SpecialToken"))
    return std::unexpected(TokError::Unsupported);
  const auto& specials = post.at("special_tokens");
  const auto first = single[0]["SpecialToken"]["id"].get<std::string>();
  const auto last = single[2]["SpecialToken"]["id"].get<std::string>();
  return std::pair{specials.at(first).at("ids")[0].get<std::int64_t>(),
                   specials.at(last).at("ids")[0].get<std::int64_t>()};
}

// ---------------------------------------------------------------- WordPiece (BERT/ELECTRA)
class WordPieceTokenizer final : public Tokenizer {
 public:
  WordPieceTokenizer(Vocab vocab, std::int64_t cls, std::int64_t sep, std::int64_t unk,
                     std::string prefix, std::size_t max_chars)
      : vocab_(std::move(vocab)), cls_(cls), sep_(sep), unk_(unk), prefix_(std::move(prefix)),
        max_chars_(max_chars), pieces_(reverse(vocab_)) {}

  std::string_view kind() const override { return "wordpiece"; }
  std::string_view piece(std::int64_t id) const override { return piece_of(pieces_, id); }
  bool is_byte_fallback(std::int64_t) const override { return false; }
  std::int64_t unk_id() const override { return unk_; }

  std::vector<Token> encode(std::span<const Unit> units) const override {
    // BertNormalizer(clean_text, handle_chinese_chars, lowercase=false, strip_accents=null)
    std::vector<Unit> norm;
    norm.reserve(units.size());
    for (const auto& u : units) {
      if (u.cp == 0 || u.cp == 0xFFFD || is_bert_control(u.cp)) continue;
      if (is_white_space(u.cp)) { norm.push_back(Unit{U' ', u.src}); continue; }
      if (is_cjk_ideograph(u.cp)) {
        norm.push_back(Unit{U' ', u.src});
        norm.push_back(u);
        norm.push_back(Unit{U' ', u.src});
        continue;
      }
      norm.push_back(u);
    }
    std::vector<Token> out;
    out.push_back(Token{cls_, {}, true});
    // BertPreTokenizer: 공백으로 나누고(제거) 구두점을 단독 단어로 분리한다.
    std::size_t i = 0;
    while (i < norm.size()) {
      if (is_white_space(norm[i].cp)) { ++i; continue; }
      std::size_t j = i + 1;
      if (!is_bert_punct(norm[i].cp))
        while (j < norm.size() && !is_white_space(norm[j].cp) && !is_bert_punct(norm[j].cp)) ++j;
      word_piece(std::span<const Unit>(norm).subspan(i, j - i), out);
      i = j;
    }
    out.push_back(Token{sep_, {}, true});
    return out;
  }

 private:
  void word_piece(std::span<const Unit> word, std::vector<Token>& out) const {
    const ByteSpan whole{word.front().src.begin, word.back().src.end};
    if (word.size() > max_chars_) { out.push_back(Token{unk_, whole, false}); return; }
    std::vector<std::string> pieces;  // 코드포인트별 UTF-8
    pieces.reserve(word.size());
    for (const auto& u : word) { std::string s; append_utf8(s, u.cp); pieces.push_back(std::move(s)); }
    std::vector<Token> sub;
    std::size_t start = 0;
    while (start < word.size()) {
      std::size_t end = word.size();
      bool found = false;
      while (start < end) {
        std::string cand = start > 0 ? prefix_ : std::string{};
        for (std::size_t k = start; k < end; ++k) cand += pieces[k];
        if (const auto it = vocab_.find(cand); it != vocab_.end()) {
          sub.push_back(Token{it->second, ByteSpan{word[start].src.begin, word[end - 1].src.end}, false});
          found = true;
          break;
        }
        --end;
      }
      if (!found) { out.push_back(Token{unk_, whole, false}); return; }  // 단어 전체를 UNK 로
      start = end;
    }
    out.insert(out.end(), sub.begin(), sub.end());
  }

  Vocab vocab_;
  std::int64_t cls_, sep_, unk_;
  std::string prefix_;
  std::size_t max_chars_;
  std::vector<std::string> pieces_;
};

// ---------------------------------------------------------------- SentencePiece 형 BPE (Gemma 계열)
class MetaspaceBpeTokenizer final : public Tokenizer {
 public:
  struct Merge { std::uint32_t rank; std::int64_t result; };

  MetaspaceBpeTokenizer(Vocab vocab, std::unordered_map<std::uint64_t, Merge> merges,
                        std::vector<std::pair<std::string, std::int64_t>> added, std::int64_t bos,
                        std::int64_t eos, std::int64_t unk)
      : vocab_(std::move(vocab)), merges_(std::move(merges)), added_(std::move(added)), bos_(bos),
        eos_(eos), unk_(unk), pieces_(reverse(vocab_)) {
    for (int b = 0; b < 256; ++b) {
      char name[8];
      std::snprintf(name, sizeof name, "<0x%02X>", b);
      const auto it = vocab_.find(std::string_view{name});
      byte_ids_[b] = it == vocab_.end() ? -1 : it->second;
    }
  }

  std::string_view kind() const override { return "metaspace-bpe"; }
  std::string_view piece(std::int64_t id) const override { return piece_of(pieces_, id); }
  bool is_byte_fallback(std::int64_t id) const override {
    const auto p = piece(id);
    return p.size() == 6 && p.starts_with("<0x") && p.ends_with(">");
  }
  std::int64_t unk_id() const override { return unk_; }

  std::vector<Token> encode(std::span<const Unit> units) const override {
    std::vector<Token> out;
    out.push_back(Token{bos_, {}, true});
    // 비특수 added token(개행 묶음 등)을 먼저 떼어낸다. 원문 기준 leftmost-longest.
    std::size_t seg_start = 0;
    std::size_t i = 0;
    while (i < units.size()) {
      const auto [len, id] = match_added(units, i);
      if (len == 0) { ++i; continue; }
      encode_segment(units.subspan(seg_start, i - seg_start), out);
      out.push_back(Token{id, ByteSpan{units[i].src.begin, units[i + len - 1].src.end}, false});
      i += len;
      seg_start = i;
    }
    encode_segment(units.subspan(seg_start), out);
    out.push_back(Token{eos_, {}, true});
    return out;
  }

 private:
  struct Sym { std::int64_t id; ByteSpan src; };

  std::pair<std::size_t, std::int64_t> match_added(std::span<const Unit> units, std::size_t at) const {
    std::size_t best_len = 0;
    std::int64_t best_id = -1;
    std::size_t best_bytes = 0;
    for (const auto& [content, id] : added_) {
      // content 를 코드포인트 단위로 맞춰 본다.
      std::size_t k = 0, pos = 0;
      bool ok = true;
      while (pos < content.size()) {
        if (at + k >= units.size()) { ok = false; break; }
        std::string one;
        append_utf8(one, units[at + k].cp);
        if (content.compare(pos, one.size(), one) != 0) { ok = false; break; }
        pos += one.size();
        ++k;
      }
      if (ok && content.size() > best_bytes) { best_bytes = content.size(); best_len = k; best_id = id; }
    }
    return {best_len, best_id};
  }

  void encode_segment(std::span<const Unit> seg, std::vector<Token>& out) const {
    if (seg.empty()) return;
    // normalizer Replace(' ' → '▁') + Metaspace(prepend_scheme=always, split=true)
    std::vector<Unit> norm;
    norm.reserve(seg.size() + 1);
    for (const auto& u : seg) norm.push_back(Unit{u.cp == U' ' ? U'▁' : u.cp, u.src});
    if (norm.front().cp != U'▁')
      norm.insert(norm.begin(), Unit{U'▁', ByteSpan{seg.front().src.begin, seg.front().src.begin}});
    std::size_t i = 0;
    while (i < norm.size()) {
      std::size_t j = i + 1;
      while (j < norm.size() && norm[j].cp != U'▁') ++j;
      bpe_word(std::span<const Unit>(norm).subspan(i, j - i), out);
      i = j;
    }
  }

  void bpe_word(std::span<const Unit> word, std::vector<Token>& out) const {
    std::vector<Sym> syms;
    for (const auto& u : word) {
      std::string s;
      append_utf8(s, u.cp);
      if (const auto it = vocab_.find(s); it != vocab_.end()) { syms.push_back(Sym{it->second, u.src}); continue; }
      // byte_fallback: 모든 바이트 토큰이 있을 때만 사용, 아니면 UNK
      bool all = true;
      for (unsigned char b : s) all = all && byte_ids_[b] >= 0;
      if (all) for (unsigned char b : s) syms.push_back(Sym{byte_ids_[b], u.src});
      else syms.push_back(Sym{unk_, u.src});
    }
    // 가장 낮은 rank 의 인접 쌍부터, 같은 rank 면 왼쪽부터 병합한다.
    while (syms.size() > 1) {
      std::uint32_t best_rank = std::numeric_limits<std::uint32_t>::max();
      std::size_t best_pos = 0;
      std::int64_t best_result = -1;
      for (std::size_t k = 0; k + 1 < syms.size(); ++k) {
        const auto key = (static_cast<std::uint64_t>(syms[k].id) << 32) | static_cast<std::uint64_t>(syms[k + 1].id);
        const auto it = merges_.find(key);
        if (it != merges_.end() && it->second.rank < best_rank) {
          best_rank = it->second.rank; best_pos = k; best_result = it->second.result;
        }
      }
      if (best_result < 0) break;
      syms[best_pos] = Sym{best_result, ByteSpan{syms[best_pos].src.begin, syms[best_pos + 1].src.end}};
      syms.erase(syms.begin() + static_cast<std::ptrdiff_t>(best_pos) + 1);
    }
    for (const auto& s : syms) out.push_back(Token{s.id, s.src, false});
  }

  Vocab vocab_;
  std::unordered_map<std::uint64_t, Merge> merges_;
  std::vector<std::pair<std::string, std::int64_t>> added_;
  std::int64_t bos_, eos_, unk_;
  std::vector<std::string> pieces_;
  std::int64_t byte_ids_[256]{};
};

std::expected<std::unique_ptr<const Tokenizer>, TokError> build(const json& j) {
  const auto& model = j.at("model");
  const auto type = model.value("type", "");
  const auto& norm = j.at("normalizer");
  const auto& pre = j.at("pre_tokenizer");
  auto wrap = wrap_ids(j.at("post_processor"));
  if (!wrap) return std::unexpected(wrap.error());

  Vocab vocab;
  if (type == "WordPiece") {
    const bool bert_norm = norm.value("type", "") == "BertNormalizer" && norm.value("clean_text", false) &&
                           norm.value("handle_chinese_chars", false) && !norm.value("lowercase", true) &&
                           (norm["strip_accents"].is_null() || norm["strip_accents"] == false);
    if (!bert_norm || pre.value("type", "") != "BertPreTokenizer") return std::unexpected(TokError::Unsupported);
    for (const auto& [k, v] : model.at("vocab").items()) vocab.emplace(k, v.get<std::int64_t>());
    auto unk = lookup(vocab, model.at("unk_token").get<std::string>());
    if (!unk) return std::unexpected(unk.error());
    return std::make_unique<WordPieceTokenizer>(std::move(vocab), wrap->first, wrap->second, *unk,
                                                model.value("continuing_subword_prefix", "##"),
                                                model.value("max_input_chars_per_word", std::size_t{100}));
  }
  if (type == "BPE") {
    const bool replace_space = norm.value("type", "") == "Replace" && norm["pattern"].value("String", "") == " " &&
                               norm.value("content", "") == "▁";
    const bool metaspace = pre.value("type", "") == "Metaspace" && pre.value("replacement", "") == "▁" &&
                           pre.value("prepend_scheme", "") == "always" && pre.value("split", false);
    if (!replace_space || !metaspace || !model.value("byte_fallback", false) ||
        model.value("ignore_merges", false) || !model["continuing_subword_prefix"].is_null() ||
        !model["end_of_word_suffix"].is_null())
      return std::unexpected(TokError::Unsupported);
    for (const auto& [k, v] : model.at("vocab").items()) vocab.emplace(k, v.get<std::int64_t>());
    std::unordered_map<std::uint64_t, MetaspaceBpeTokenizer::Merge> merges;
    std::uint32_t rank = 0;
    for (const auto& m : model.at("merges")) {
      std::string a, b;
      if (m.is_array()) { a = m[0].get<std::string>(); b = m[1].get<std::string>(); }
      else { const auto s = m.get<std::string>(); const auto sp = s.find(' '); a = s.substr(0, sp); b = s.substr(sp + 1); }
      auto ia = lookup(vocab, a), ib = lookup(vocab, b), ir = lookup(vocab, a + b);
      if (!ia || !ib || !ir) return std::unexpected(TokError::MissingToken);
      const auto key = (static_cast<std::uint64_t>(*ia) << 32) | static_cast<std::uint64_t>(*ib);
      merges.try_emplace(key, MetaspaceBpeTokenizer::Merge{rank, *ir});  // 먼저 나온 rank 우선
      ++rank;
    }
    std::vector<std::pair<std::string, std::int64_t>> added;
    for (const auto& a : j.at("added_tokens")) {
      if (a.value("special", false)) continue;  // special 은 사용자 텍스트에서 해석하지 않는다
      if (a.value("normalized", true) || a.value("single_word", false) || a.value("lstrip", false) ||
          a.value("rstrip", false))
        return std::unexpected(TokError::Unsupported);
      added.emplace_back(a.at("content").get<std::string>(), a.at("id").get<std::int64_t>());
    }
    auto unk = lookup(vocab, model.at("unk_token").get<std::string>());
    if (!unk) return std::unexpected(unk.error());
    return std::make_unique<MetaspaceBpeTokenizer>(std::move(vocab), std::move(merges), std::move(added),
                                                   wrap->first, wrap->second, *unk);
  }
  return std::unexpected(TokError::Unsupported);
}

}  // namespace

std::expected<std::unique_ptr<const Tokenizer>, TokError> load_tokenizer(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::unexpected(TokError::FileOpen);
  try {
    const auto j = json::parse(in);
    return build(j);
  } catch (const json::exception&) {
    // 라이브러리 예외는 경계에서 값으로 바꾼다.
    return std::unexpected(TokError::Parse);
  }
}

std::string_view to_string(TokError e) {
  switch (e) {
    case TokError::FileOpen: return "file-open";
    case TokError::Parse: return "parse";
    case TokError::Unsupported: return "unsupported-config";
    case TokError::MissingToken: return "missing-token";
  }
  return "unknown";
}

}  // namespace prompt_airlock::ner
