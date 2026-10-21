// 긴 보기를 모델 한 번 입력 안에 들어가는 창으로 나눈다(Phase 7-2). 입출력 없는 순수 함수.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace prompt_airlock::ner {

// 창 하나의 본문 토큰 한도. 앞뒤 special 2개를 더하면 256 으로, 합격 기준(D5) 지연 측정 길이와 같다.
inline constexpr std::uint32_t window_body_tokens = 254;
// 문장 하나가 창보다 길어 문장 중간에서 자를 때 앞 창과 겹치는 토큰 수. 경계에 걸린 이름을 다음 창이 온전히 본다.
inline constexpr std::uint32_t window_overlap_tokens = 32;
// 구간 하나에서 만들 수 있는 창 수. 넘으면 과부하로 거절한다(64 KiB 한도 안의 보통 글은 수십 개).
inline constexpr std::size_t max_ner_windows = 128;

// 본문 토큰 [first, end).
struct TokenWindow {
    std::uint32_t first;
    std::uint32_t end;
    bool operator==(const TokenWindow&) const noexcept = default;
};

// tokens 는 본문 토큰 수, cut_after 는 그 뒤에서 잘라도 되는 토큰 위치(문장 끝)를 오름차순으로 담는다.
// 창은 window_body_tokens 안에서 가장 늦은 문장 끝에서 자르고, 문장 끝이 없으면 그 자리에서 자른 뒤
// window_overlap_tokens 만큼 되돌아가 다음 창을 시작한다. 창이 max_ner_windows 를 넘으면 nullopt.
[[nodiscard]] std::optional<std::vector<TokenWindow>> split_windows(std::uint32_t tokens,
                                                                    std::span<const std::uint32_t> cut_after);

}  // namespace prompt_airlock::ner
