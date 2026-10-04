#include "text.hpp"

#include <cstdlib>
#include <memory>

#include <utf8proc.h>

namespace prompt_airlock::ner {
namespace {

struct FreeDeleter {
  void operator()(utf8proc_uint8_t* p) const { std::free(p); }
};

// utf8proc 로 NFC 를 적용한다. 입력은 이미 검증된 UTF-8 이다.
std::expected<std::u32string, TextError> nfc_codepoints(std::string_view utf8, bool compat) {
  utf8proc_uint8_t* raw = nullptr;
  const auto n = utf8proc_map(reinterpret_cast<const utf8proc_uint8_t*>(utf8.data()),
                              static_cast<utf8proc_ssize_t>(utf8.size()), &raw,
                              static_cast<utf8proc_option_t>(UTF8PROC_STABLE | UTF8PROC_COMPOSE |
                                                              (compat ? UTF8PROC_COMPAT : 0)));
  std::unique_ptr<utf8proc_uint8_t, FreeDeleter> owned(raw);
  if (n < 0) return std::unexpected(TextError::NormalizationFailed);
  std::u32string out;
  utf8proc_ssize_t pos = 0;
  while (pos < n) {
    utf8proc_int32_t cp = 0;
    const auto k = utf8proc_iterate(owned.get() + pos, n - pos, &cp);
    if (k <= 0) return std::unexpected(TextError::NormalizationFailed);
    out.push_back(static_cast<char32_t>(cp));
    pos += k;
  }
  return out;
}

// 이 코드포인트 앞에서 NFC 가 경계를 넘어 합성·재배열하지 않는가.
// ccc==0 이고 합성의 두 번째 요소가 될 수 없으면 독립 구간을 시작할 수 있다.
bool starts_segment(char32_t cp) {
  if (cp >= 0x1160 && cp <= 0x11FF) return false;  // 한글 중성·종성 자모
  if (cp >= 0xD7B0 && cp <= 0xD7FF) return false;  // 한글 자모 확장-B
  const auto* p = utf8proc_get_property(static_cast<utf8proc_int32_t>(cp));
  return p->combining_class == 0 && !p->comb_issecond;
}

}  // namespace

bool is_zero_width(char32_t cp) {
  return cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0x2060 || cp == 0xFEFF;
}

bool is_hangul_syllable(char32_t cp) { return cp >= 0xAC00 && cp <= 0xD7A3; }

void append_utf8(std::string& out, char32_t cp) {
  if (cp < 0x80) {
    out.push_back(static_cast<char>(cp));
  } else if (cp < 0x800) {
    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else if (cp < 0x10000) {
    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  } else {
    out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  }
}

std::string to_utf8(std::span<const Unit> units) {
  std::string out;
  out.reserve(units.size() * 3);
  for (const auto& u : units) append_utf8(out, u.cp);
  return out;
}

std::expected<std::vector<Unit>, TextError> decode_utf8(std::string_view text) {
  std::vector<Unit> out;
  out.reserve(text.size());
  const auto* s = reinterpret_cast<const unsigned char*>(text.data());
  const std::size_t n = text.size();
  std::size_t i = 0;
  while (i < n) {
    const unsigned char b = s[i];
    char32_t cp = 0;
    std::size_t len = 0;
    char32_t min = 0;
    if (b < 0x80) { cp = b; len = 1; }
    else if ((b & 0xE0) == 0xC0) { cp = b & 0x1F; len = 2; min = 0x80; }
    else if ((b & 0xF0) == 0xE0) { cp = b & 0x0F; len = 3; min = 0x800; }
    else if ((b & 0xF8) == 0xF0) { cp = b & 0x07; len = 4; min = 0x10000; }
    else return std::unexpected(TextError::InvalidUtf8);
    if (i + len > n) return std::unexpected(TextError::InvalidUtf8);
    for (std::size_t k = 1; k < len; ++k) {
      if ((s[i + k] & 0xC0) != 0x80) return std::unexpected(TextError::InvalidUtf8);
      cp = (cp << 6) | (s[i + k] & 0x3F);
    }
    // overlong, surrogate, 범위 초과를 거부한다.
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
      return std::unexpected(TextError::InvalidUtf8);
    out.push_back(Unit{cp, ByteSpan{Utf8ByteOffset{i}, Utf8ByteOffset{i + len}}});
    i += len;
  }
  return out;
}

std::expected<std::vector<Unit>, TextError> normalize(std::string_view original, NormPolicy policy) {
  auto decoded = decode_utf8(original);
  if (!decoded) return std::unexpected(decoded.error());

  std::vector<Unit> kept;
  kept.reserve(decoded->size());
  for (const auto& u : *decoded)
    if (!(policy.strip_zero_width && is_zero_width(u.cp))) kept.push_back(u);
  if (!policy.nfc) return kept;

  // 합성이 넘지 않는 구간으로 나눠 구간별로 NFC 를 적용한다.
  // 구간 결과의 모든 코드포인트는 구간 전체 원문 범위를 받는다(좁히지 않고 넓히는 방향).
  std::vector<Unit> out;
  out.reserve(kept.size());
  std::string whole;
  std::size_t i = 0;
  while (i < kept.size()) {
    std::size_t j = i + 1;
    while (j < kept.size() && !starts_segment(kept[j].cp)) ++j;
    std::string seg;
    for (std::size_t k = i; k < j; ++k) append_utf8(seg, kept[k].cp);
    whole += seg;
    auto composed = nfc_codepoints(seg, policy.compat);
    if (!composed) return std::unexpected(composed.error());
    const ByteSpan src{kept[i].src.begin, kept[j - 1].src.end};
    for (char32_t cp : *composed) out.push_back(Unit{cp, src});
    i = j;
  }
  // 구간별 결과가 전체 NFC 와 다르면 경계 가정이 깨진 것이므로 실패시킨다.
  auto reference = nfc_codepoints(whole, policy.compat);
  if (!reference || reference->size() != out.size())
    return std::unexpected(TextError::NormalizationFailed);
  for (std::size_t k = 0; k < out.size(); ++k)
    if ((*reference)[k] != out[k].cp) return std::unexpected(TextError::NormalizationFailed);
  return out;
}

bool is_codepoint_boundary(std::string_view text, Utf8ByteOffset at) {
  if (at.value > text.size()) return false;
  if (at.value == text.size()) return true;
  return (static_cast<unsigned char>(text[at.value]) & 0xC0) != 0x80;
}

CodepointOffset to_codepoint_offset(std::string_view text, Utf8ByteOffset at) {
  std::size_t count = 0;
  for (std::size_t i = 0; i < at.value && i < text.size(); ++i)
    if ((static_cast<unsigned char>(text[i]) & 0xC0) != 0x80) ++count;
  return CodepointOffset{count};
}

}  // namespace prompt_airlock::ner
