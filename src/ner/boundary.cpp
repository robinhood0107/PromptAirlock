#include "prompt_airlock/ner/boundary.hpp"

#include <utf8proc.h>

#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "prompt_airlock/core/particle.hpp"
#include "prompt_airlock/detect/organization.hpp"

namespace prompt_airlock::ner {
namespace {

namespace pc = core;

// 떼고 나서 남아야 하는 최소 글자 수. 한국어 이름·기관명은 두 글자 이상이다.
constexpr std::uint32_t min_name = 2;

// 아래 목록은 이 저장소의 시험 셋이 아니라 일반적인 한국어 표기에서 가져왔다(결정 #107: 측정 부풀림 방지).
// 긴 것을 먼저 둔다.

// 서술격 조사와 그 활용. 이름 바로 뒤에 붙는다(윤서연입니다).
// 조사 후처리가 먼저 '는' 을 떼면 '이라' 가 남으므로(윤서연이라는 → 윤서연이라) '이라' 도 둔다.
constexpr std::array<std::u32string_view, 16> copulas = {
    U"이었습니다", U"였습니다", U"입니다", U"입니까", U"이었다", U"이에요", U"이라는", U"이라고",
    U"였다", U"예요", U"이다", U"이라", U"이야", U"이고", U"이며", U"라는",
};

// 사람 이름 뒤 호칭. 님·씨는 core 조사 후처리가 뗀다.
constexpr std::array<std::u32string_view, 1> honorifics = {U"께"};

// 직함. 사람 이름에 붙여 쓰거나(신태호주무관) 띄어 쓴다(Jiho Park 대리). 공공·기업·학교·의료·법률의 일반 직함이다.
constexpr std::array<std::u32string_view, 85> titles = {
    U"부이사관", U"대표이사", U"이사장", U"부회장", U"부사장", U"부총장", U"부원장", U"본부장", U"파트장", U"그룹장",
    U"센터장", U"지점장", U"지사장", U"구청장", U"도지사", U"부의장", U"연구위원", U"연구원", U"부교수", U"조교수",
    U"선생님", U"주무관", U"사무관", U"서기관", U"이사관", U"위원장", U"매니저", U"간호사", U"변호사", U"회계사",
    U"세무사", U"변리사", U"노무사", U"관장", U"회장", U"사장", U"대표", U"이사", U"상무", U"전무",
    U"감사", U"고문", U"실장", U"부장", U"차장", U"과장", U"대리", U"주임", U"사원", U"팀장",
    U"팀원", U"책임", U"선임", U"수석", U"인턴", U"프로", U"교수", U"강사", U"박사", U"선생",
    U"총장", U"학장", U"원장", U"소장", U"국장", U"처장", U"청장", U"장관", U"차관", U"시장",
    U"군수", U"의원", U"의장", U"위원", U"계장", U"반장", U"조장", U"점장", U"의사", U"약사",
    U"검사", U"판사", U"기자", U"작가", U"감독",
};

// 기관명 앞 법인 표기. (주) 같은 괄호 약칭은 skip_legal_prefix 가 따로 본다.
constexpr std::array<std::u32string_view, 8> legal_forms = {
    U"주식회사", U"유한회사", U"합자회사", U"합명회사", U"재단법인", U"사단법인", U"학교법인", U"의료법인",
};
constexpr std::array<char32_t, 4> legal_short = {U'주', U'유', U'재', U'사'};

// 기관명 뒤에 띄어 쓴 부서명의 끝(다온에너지 보안팀).
constexpr std::array<std::u32string_view, 13> department_endings = {
    U"사업부", U"연구실", U"협력단", U"사업단", U"사무국", U"본부", U"센터", U"부서", U"지사", U"지점", U"지부", U"팀",
    U"실",
};

// 일반 업무 낱말. 이것들을 이어 붙인 말 + 부서 끝말로만 된 구간(영업본부, 고객센터, 기술지원팀)은 이름이 아니다.
// 기관명 바로 뒤에 띄어 쓴 부서명을 떼고 나면, 보호한 글을 다시 탐지할 때 모델이 token 옆의 부서명만 기관으로 볼 수 있다.
// 그대로 두면 정상 요청이 잔여 검사에서 거절된다. "한빛센터" 같은 진짜 기관명은 앞 낱말이 이 목록에 없어 남는다.
constexpr std::array<std::u32string_view, 37> generic_units = {
    U"마케팅", U"디자인", U"영업", U"기획", U"인사", U"총무", U"재무", U"회계", U"보안", U"고객", U"기술", U"개발", U"홍보",
    U"경영", U"전략", U"품질", U"생산", U"구매", U"법무", U"감사", U"연구", U"운영", U"지원", U"정보", U"전산", U"교육",
    U"상담", U"관리", U"사업", U"서비스", U"시스템", U"플랫폼", U"제품", U"설계", U"안전", U"환경", U"대외",
};

// word 가 일반 업무 낱말을 하나 이상 이어 붙인 말인가(기술지원, 영업관리).
[[nodiscard]] bool is_generic_compound(std::u32string_view word) noexcept {
    if (word.empty()) {
        return true;
    }
    for (const auto g : generic_units) {
        if (word.starts_with(g) && is_generic_compound(word.substr(g.size()))) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] utf8proc_category_t category(char32_t c) noexcept {
    return utf8proc_category(static_cast<utf8proc_int32_t>(c));
}

// 글자·숫자·결합 표지면 어절 안의 글자다. 공백·문장 부호·기호에서 어절이 끊긴다.
[[nodiscard]] bool is_word_char(char32_t c) noexcept {
    switch (category(c)) {
        case UTF8PROC_CATEGORY_LU:
        case UTF8PROC_CATEGORY_LL:
        case UTF8PROC_CATEGORY_LT:
        case UTF8PROC_CATEGORY_LM:
        case UTF8PROC_CATEGORY_LO:
        case UTF8PROC_CATEGORY_MN:
        case UTF8PROC_CATEGORY_MC:
        case UTF8PROC_CATEGORY_ME:
        case UTF8PROC_CATEGORY_ND:
        case UTF8PROC_CATEGORY_NL:
        case UTF8PROC_CATEGORY_NO:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool is_space(char32_t c) noexcept { return category(c) == UTF8PROC_CATEGORY_ZS || c == U'\t'; }

// 보기 구간 [first, last] 를 다루는 작은 도우미. 구간은 늘 비어 있지 않다(first <= last).
class Span {
public:
    Span(const detect::DetectionView& view, std::uint32_t first, std::uint32_t last)
        : units_(view.units), first_(first), last_(last) {}

    [[nodiscard]] std::uint32_t first() const noexcept { return first_; }
    [[nodiscard]] std::uint32_t last() const noexcept { return last_; }
    [[nodiscard]] std::uint32_t size() const noexcept { return last_ - first_ + 1; }
    [[nodiscard]] char32_t at(std::uint32_t i) const noexcept { return units_[i].value; }

    [[nodiscard]] bool ends_with(std::u32string_view s) const noexcept {
        if (size() < s.size()) {
            return false;
        }
        const auto from = last_ + 1 - static_cast<std::uint32_t>(s.size());
        for (std::size_t k = 0; k < s.size(); ++k) {
            if (at(from + static_cast<std::uint32_t>(k)) != s[k]) {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool starts_with(std::u32string_view s) const noexcept {
        if (size() < s.size()) {
            return false;
        }
        for (std::size_t k = 0; k < s.size(); ++k) {
            if (at(first_ + static_cast<std::uint32_t>(k)) != s[k]) {
                return false;
            }
        }
        return true;
    }

    // 끝에서 n 글자를 뗀다. min_name 글자가 남지 않으면 그대로 둔다.
    bool drop_tail(std::uint32_t n) noexcept {
        if (size() < n + min_name) {
            return false;
        }
        last_ -= n;
        return true;
    }

    // 앞에서 n 글자와 그 뒤 공백을 뗀다. min_name 글자가 남지 않으면 그대로 둔다.
    bool drop_head(std::uint32_t n) noexcept {
        auto next = first_ + n;
        while (next <= last_ && is_space(at(next))) {
            ++next;
        }
        if (next > last_ || last_ - next + 1 < min_name) {
            return false;
        }
        first_ = next;
        return true;
    }

    // 마지막 어절(마지막 공백 뒤)의 시작. 공백이 없으면 nullopt.
    [[nodiscard]] std::optional<std::uint32_t> last_word_start() const noexcept {
        for (auto i = last_; i > first_; --i) {
            if (is_space(at(i - 1))) {
                return i;
            }
        }
        return std::nullopt;
    }

    // 마지막 어절과 그 앞 공백을 뗀다.
    bool drop_last_word() noexcept {
        const auto start = last_word_start();
        if (!start) {
            return false;
        }
        auto end = *start - 1;  // 공백
        while (end > first_ && is_space(at(end))) {
            --end;
        }
        if (is_space(at(end)) || end - first_ + 1 < min_name) {
            return false;
        }
        last_ = end;
        return true;
    }

    // core 조사·호칭 후처리를 적용하고, 줄어든 byte 끝에 맞춰 last 를 옮긴다.
    bool trim_particles(const detect::DetectionView& view) noexcept {
        const auto span = detect::source_span(view, first_, last_);
        const auto trimmed = pc::trim_trailing_particles(view.units, span);
        if (trimmed.end() == span.end()) {
            return false;
        }
        while (last_ > first_ && units_[last_].source.begin() >= trimmed.end()) {
            --last_;
        }
        return true;
    }

private:
    const std::vector<pc::DecodedCodepoint>& units_;
    std::uint32_t first_;
    std::uint32_t last_;
};

// 모델이 어절 일부만 잡거나("다" ← 다온제약을) 앞뒤 부호까지 잡은(")누리별대학교") 구간을 어절 경계로 맞춘다.
[[nodiscard]] std::optional<std::pair<std::uint32_t, std::uint32_t>> to_word(const detect::DetectionView& view,
                                                                           std::uint32_t first, std::uint32_t last) {
    const auto word = [&](std::uint32_t i) { return is_word_char(view.units[i].value); };
    while (first < last && !word(first)) {
        ++first;
    }
    while (last > first && !word(last)) {
        --last;
    }
    if (!word(first)) {
        return std::nullopt;
    }
    while (first > 0 && word(first - 1)) {
        --first;
    }
    while (last + 1 < view.units.size() && word(last + 1)) {
        ++last;
    }
    return std::pair{first, last};
}

// 꼬리 목록 중 맞는 첫 번째를 뗀다.
template <std::size_t N>
bool drop_any_tail(Span& span, const std::array<std::u32string_view, N>& list) {
    for (const auto s : list) {
        if (span.ends_with(s) && span.drop_tail(static_cast<std::uint32_t>(s.size()))) {
            return true;
        }
    }
    return false;
}

// 법인 표기: 주식회사 ○○, (주)○○. 괄호 약칭은 여는 괄호가 어절 맞춤에서 이미 빠져 "주)" 로 시작한다.
void skip_legal_prefix(const detect::DetectionView& view, Span& span) {
    for (const auto form : legal_forms) {
        if (span.starts_with(form) && span.drop_head(static_cast<std::uint32_t>(form.size()))) {
            return;
        }
    }
    const auto f = span.first();
    const bool opened = f > 0 && view.units[f - 1].value == U'(';
    if (opened && span.size() > 2 && span.at(f + 1) == U')') {
        for (const auto c : legal_short) {
            if (span.at(f) == c) {
                span.drop_head(2);
                return;
            }
        }
    }
}

}  // namespace

pc::EntityType corrected_type(const detect::DetectionView& view, pc::ByteSpan span, pc::EntityType type) {
    if (type != pc::EntityType::Person) {
        return type;
    }
    std::u32string word;
    for (const auto& u : view.units) {
        if (span.contains(u.source)) {
            word.push_back(u.value);
        }
    }
    const auto tail = detect::org_tail_length(word, detect::OrgTails::Broad);
    return tail > 0 && word.size() >= tail + min_name ? pc::EntityType::Organization : type;
}

std::optional<pc::ByteSpan> name_span(const detect::DetectionView& view, std::uint32_t first, std::uint32_t last,
                                      pc::EntityType type) {
    const auto word = to_word(view, first, last);
    if (!word) {
        return std::nullopt;
    }
    Span span(view, word->first, word->second);
    const bool person = type == pc::EntityType::Person;
    if (!person) {
        skip_legal_prefix(view, span);
    }
    // 하나를 떼면 그 앞 꼬리가 드러날 수 있다(김민수님께 → 김민수님 → 김민수). 더 줄지 않을 때까지 되풀이한다.
    for (bool changed = true; changed;) {
        changed = span.trim_particles(view);
        changed = drop_any_tail(span, copulas) || changed;
        // 받침 없는 이름이나 영문 뒤 서술격 '다'(최종 승인자는 편단우다). 받침이 있으면 '이다' 가 된다.
        if (span.size() >= min_name + 1 && span.ends_with(U"다")) {
            const auto prev = span.at(span.last() - 1);
            const bool open_syllable = prev >= 0xAC00 && prev <= 0xD7A3 && (prev - 0xAC00) % 28 == 0;
            const bool latin = (prev >= U'a' && prev <= U'z') || (prev >= U'A' && prev <= U'Z');
            changed = ((open_syllable || latin) && span.drop_tail(1)) || changed;
        }
        if (const auto start = span.last_word_start()) {
            // 띄어 쓴 직함(사람·기관 모두), 띄어 쓴 부서명(기관).
            Span last_word(view, *start, span.last());
            bool drop = false;
            for (const auto t : titles) {
                drop = drop || (last_word.size() == t.size() && last_word.starts_with(t));
            }
            if (!person) {
                for (const auto d : department_endings) {
                    drop = drop || last_word.ends_with(d);
                }
            }
            changed = (drop && span.drop_last_word()) || changed;
        }
        if (person) {
            changed = drop_any_tail(span, honorifics) || changed;
            changed = drop_any_tail(span, titles) || changed;  // 붙여 쓴 직함(신태호주무관)
            // 숫자가 붙은 직함(진지우9팀장)에서 직함을 뗀 뒤 남은 숫자. 사람 이름은 숫자로 끝나지 않는다.
            while (span.at(span.last()) >= U'0' && span.at(span.last()) <= U'9' && span.drop_tail(1)) {
                changed = true;
            }
        }
    }
    if (!person && !span.last_word_start()) {
        std::u32string word;
        for (auto i = span.first(); i <= span.last(); ++i) {
            word.push_back(span.at(i));
        }
        for (const auto d : department_endings) {
            if (word.size() > d.size() && word.ends_with(d) && is_generic_compound(std::u32string_view(word).substr(0, word.size() - d.size()))) {
                return std::nullopt;  // 부서명뿐이다
            }
        }
    }
    return detect::source_span(view, span.first(), span.last());
}

}  // namespace prompt_airlock::ner
