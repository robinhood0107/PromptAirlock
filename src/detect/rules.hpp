// 탐지기 내부 공통 타입. 공개하지 않는다(include/ 에 없음).
#pragma once

#include <algorithm>
#include <compare>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/types.hpp"
#include "prompt_airlock/detect/scan.hpp"
#include "prompt_airlock/detect/sensitive.hpp"
#include "prompt_airlock/detect/terms.hpp"
#include "prompt_airlock/detect/view.hpp"

namespace prompt_airlock::detect::rules {

// 보기 위치 [first, last] 의 탐지 결과. 원문 위치로는 detectors.cpp 가 바꾼다.
struct Hit {
    std::uint32_t first;
    std::uint32_t last;
    core::EntityType type;
    core::DetectorKind kind;
    auto operator<=>(const Hit&) const noexcept = default;
};

// text 는 view.units 의 글자만 모은 문자열이다(위치가 같다). runs 는 digit_runs(view).
void find_identifiers(std::span<const DigitRun> runs, std::u32string_view text, std::vector<Hit>& out);

// 묶음 [a, b] 를 이어 붙인 숫자가 max_digit_run 이하인 모든 구간을 차례로 본다. 구간 수는 묶음 수 × 34 이하.
template <class F>
void for_each_window(const DigitRun& run, F&& fn) {
    for (std::size_t a = 0; a < run.groups.size(); ++a) {
        std::string d;
        for (std::size_t b = a; b < run.groups.size(); ++b) {
            d += run.groups[b].digits;
            if (d.size() > max_digit_run) {
                break;
            }
            fn(a, b, std::string_view(d));
        }
    }
}

// 문맥어 위치. first 순으로 정렬하고, 앞에서부터의 last 최댓값을 둬 "창 안에 문맥어가 있나"를 O(log n) 에 답한다.
class Nearby {
public:
    explicit Nearby(std::vector<TermHit> hits) : hits_(std::move(hits)) {
        std::ranges::sort(hits_, {}, &TermHit::first_unit);
        max_last_.reserve(hits_.size());
        std::uint32_t m = 0;
        for (const auto& h : hits_) {
            m = std::max(m, h.last_unit);
            max_last_.push_back(m);
        }
    }
    // [first, last] 에서 window 글자 안에 걸친 문맥어가 있고, 그 사이에 종결 부호가 없는가(clause 가 같음).
    // 문맥어는 짧으므로(64자 미만) 창 앞뒤의 문맥어만 거꾸로 훑는다.
    [[nodiscard]] bool around_in_clause(std::size_t first, std::size_t last, std::size_t window,
                                        std::span<const std::uint32_t> clause) const {
        constexpr std::size_t max_term = 64;
        auto it = std::ranges::upper_bound(hits_, last + window, {}, &TermHit::first_unit);
        while (it != hits_.begin()) {
            --it;
            if (it->first_unit + max_term + window < first) {
                break;
            }
            if (it->last_unit + window >= first && clause[it->first_unit] == clause[first]) {
                return true;
            }
        }
        return false;
    }
    // [first, last] 에서 window 글자 안에 걸친 문맥어가 있는가.
    [[nodiscard]] bool around(std::size_t first, std::size_t last, std::size_t window) const {
        const auto end = std::ranges::upper_bound(hits_, last + window, {}, &TermHit::first_unit);
        const auto n = static_cast<std::size_t>(end - hits_.begin());
        return n > 0 && max_last_[n - 1] + window >= first;
    }

private:
    std::vector<TermHit> hits_;
    std::vector<std::uint32_t> max_last_;
};

// 전화번호 대역(identifiers.cpp)과 사업자등록번호 검증 자리. 계좌 판정이 겹침 규칙에 쓴다.
[[nodiscard]] bool is_phone_number(std::string_view digits) noexcept;
[[nodiscard]] bool is_business_number(std::string_view digits) noexcept;
void find_network(std::u32string_view text, std::vector<Hit>& out);
void find_accounts(std::span<const DigitRun> runs, std::u32string_view text, const TermMatcher& context_terms,
                   const DetectionView& view, std::vector<Hit>& out);
struct SensitiveMatchers {
    const TermMatcher& categories;  // data::sensitive_terms 순서
    const TermMatcher& honorifics;
    const TermMatcher& self_statements;
};
// identities 는 이 segment 에서 먼저 찾은 결과다(식별 정보를 개인 표지로 쓴다).
void find_sensitive(const DetectionView& view, std::u32string_view text, const SensitiveMatchers& matchers,
                    std::span<const Hit> identities, std::vector<Hit>& out, SensitiveTally& tally);
void find_credentials(std::u32string_view text, const TermMatcher& secret_markers, const TermMatcher& user_markers,
                      const TermMatcher& account_markers, const DetectionView& view, std::vector<Hit>& out);
void find_secrets(std::u32string_view text, std::vector<Hit>& out);
// 기관명: 앞말 + 기관 꼬리(바름제약, Bluewave솔루션즈)인 어절과, (주)·주식회사 뒤 어절. NER 이 놓친 기관을 보탠다
// (Phase 7-3). 꼬리 목록은 organization.hpp.
void find_organizations(const DetectionView& view, std::u32string_view text, std::vector<Hit>& out);

}  // namespace prompt_airlock::detect::rules
