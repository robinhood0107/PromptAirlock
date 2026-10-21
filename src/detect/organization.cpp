#include "prompt_airlock/detect/organization.hpp"

#include <array>

#include "prompt_airlock/core/particle.hpp"
#include "rules.hpp"

namespace prompt_airlock::detect {
namespace {

// 앞말 + 꼬리로만 기관이라고 정해도 되는 꼬리. 긴 것을 먼저 둔다.
constexpr std::array<std::u32string_view, 38> strict_tails = {
    U"엔터테인먼트", U"정보기술", U"네트웍스", U"솔루션즈", U"시스템즈", U"파트너스", U"엔지니어링", U"대학교", U"대학원",
    U"의료원", U"연구소", U"연구원", U"홀딩스", U"컨설팅", U"컴퍼니", U"중공업", U"모터스", U"솔루션", U"시스템", U"바이오",
    U"코리아", U"소프트", U"랩스", U"병원", U"은행", U"증권", U"재단", U"협회", U"학회", U"공사", U"공단", U"그룹", U"전자",
    U"물산", U"건설", U"해운", U"제약", U"테크",
};

// 모델이 이미 찾은 구간의 종류만 바로잡을 때 더 받는 꼬리. 일반어와 붙어 쓰이기 쉬워 규칙 단독으로는 쓰지 않는다.
constexpr std::array<std::u32string_view, 15> broad_extra_tails = {
    U"디자인", U"에너지", U"보험", U"카드", U"산업", U"통신", U"화학", U"물류", U"식품", U"항공", U"호텔", U"신문",
    U"방송", U"출판", U"학원",
};

// 꼬리 앞에 와도 고유한 이름이 아닌 일반어(종합병원, 시중은행, 국립대학교 등).
constexpr std::array<std::u32string_view, 58> generic_heads = {
    U"종합", U"대형", U"중소", U"중견", U"시중", U"국책", U"지방", U"지역", U"국립", U"사립", U"공립", U"시립", U"도립",
    U"구립", U"민간", U"공공", U"정부", U"국영", U"해외", U"국내", U"외국", U"외국계", U"동네", U"근처", U"인근", U"주변",
    U"해당", U"일반", U"전문", U"주요", U"대학", U"부속", U"협력", U"관련", U"소속", U"거래", U"경쟁", U"신규", U"기존",
    U"계열", U"자회사", U"모회사", U"지주", U"인터넷", U"저축", U"상호", U"동물", U"치과", U"한방", U"요양", U"정신",
    U"대기업", U"벤처", U"다국적", U"글로벌", U"우리", U"저희", U"다른",
};

// (주) 같은 괄호 약칭 뒤, 또는 주식회사 같은 법인 표기 다음 어절은 기관명이다.
constexpr std::array<std::u32string_view, 8> legal_forms = {
    U"주식회사", U"유한회사", U"합자회사", U"합명회사", U"재단법인", U"사단법인", U"학교법인", U"의료법인",
};
constexpr std::array<std::u32string_view, 4> legal_short = {U"(주)", U"(유)", U"(재)", U"(사)"};

[[nodiscard]] constexpr bool is_hangul(char32_t c) noexcept { return c >= 0xAC00 && c <= 0xD7A3; }
[[nodiscard]] constexpr bool is_ascii_alnum(char32_t c) noexcept {
    return (c >= U'0' && c <= U'9') || (c >= U'A' && c <= U'Z') || (c >= U'a' && c <= U'z');
}
// 기관명 어절에 들어가는 글자. 정규화(NFKC) 뒤라 전각 영문도 여기서는 반각이다.
[[nodiscard]] constexpr bool is_name_char(char32_t c) noexcept { return is_hangul(c) || is_ascii_alnum(c) || c == U'&'; }

template <std::size_t N>
[[nodiscard]] std::size_t longest_tail(std::u32string_view word, const std::array<std::u32string_view, N>& tails) noexcept {
    std::size_t best = 0;
    for (const auto t : tails) {
        if (t.size() > best && word.ends_with(t)) {
            best = t.size();
        }
    }
    return best;
}

// 꼬리 앞말이 이름으로 볼 만한가: 한글 두 글자 이상이거나, 대문자·숫자가 든 영문 약칭(K, NX, J&P).
[[nodiscard]] bool is_name_head(std::u32string_view head) noexcept {
    if (head.empty()) {
        return false;
    }
    for (const auto g : generic_heads) {
        if (head == g) {
            return false;
        }
    }
    bool ascii = true;
    bool marked = false;
    for (const auto c : head) {
        ascii = ascii && (is_ascii_alnum(c) || c == U'&');
        marked = marked || (c >= U'A' && c <= U'Z') || (c >= U'0' && c <= U'9');
    }
    return ascii ? marked : head.size() >= 2;
}

}  // namespace

std::size_t org_tail_length(std::u32string_view word, OrgTails tails) noexcept {
    const auto strict = longest_tail(word, strict_tails);
    if (tails == OrgTails::Strict) {
        return strict;
    }
    const auto extra = longest_tail(word, broad_extra_tails);
    return strict > extra ? strict : extra;
}

namespace rules {

void find_organizations(const DetectionView& view, std::u32string_view text, std::vector<Hit>& out) {
    const auto n = static_cast<std::uint32_t>(text.size());
    std::uint32_t prev_first = 0;
    std::uint32_t prev_last = 0;
    bool has_prev = false;
    for (std::uint32_t s = 0; s < n;) {
        if (!is_name_char(text[s])) {
            ++s;
            continue;
        }
        std::uint32_t e = s;
        while (e + 1 < n && is_name_char(text[e + 1])) {
            ++e;
        }
        const auto next = e + 1;
        // 어절 끝 조사를 뗀다(바름제약을 → 바름제약).
        const auto whole = source_span(view, s, e);
        const auto trimmed = core::trim_trailing_particles(view.units, whole);
        auto last = e;
        while (last > s && view.units[last].source.begin() >= trimmed.end()) {
            --last;
        }
        const auto word = text.substr(s, last - s + 1);

        bool after_legal_form = false;
        for (const auto form : legal_short) {
            after_legal_form = after_legal_form || (s >= form.size() && text.substr(s - form.size(), form.size()) == form);
        }
        if (has_prev) {
            const auto prev = text.substr(prev_first, prev_last - prev_first + 1);
            for (const auto form : legal_forms) {
                after_legal_form = after_legal_form || prev == form;
            }
        }
        const auto tail = org_tail_length(word, OrgTails::Strict);
        const bool by_tail = tail > 0 && tail < word.size() && is_name_head(word.substr(0, word.size() - tail));
        const bool by_form = after_legal_form && word.size() >= 2;
        if (by_tail || by_form) {
            out.push_back({s, last, core::EntityType::Organization, core::DetectorKind::Pattern});
        }
        prev_first = s;
        prev_last = last;
        has_prev = true;
        s = next;
    }
}

}  // namespace rules
}  // namespace prompt_airlock::detect
