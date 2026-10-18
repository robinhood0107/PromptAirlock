#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/reason.hpp"
#include "prompt_airlock/core/token.hpp"

namespace prompt_airlock::core {

// 응답 속 token 이 놓인 문맥. None 이 아니면 복원하지 않고 응답 전체를 거절한다(ADR 0017 8번).
enum class LinkContext : std::uint8_t {
    None,
    MarkdownDestination,  // [글](주소), ![글](주소) 의 주소
    MarkdownReference,    // [이름]: 주소
    AngleBracket,         // <...> 자동 링크
    SchemeUrl,            // scheme://..., mailto:·data: 등 고정 scheme
    WwwUrl,               // www.
    HostPath,             // 이름.tld 뒤에 / ? # :포트
    HtmlTag,              // <태그 ...> 안 어디든(속성 종류와 상관없음)
    CssUrl,               // url(...), image-set(...), @import
};

// 응답을 한 번 훑어 byte 마다 문맥을 칠한 뒤, token 마다 자기 구간에 칠해진 문맥을 돌려준다.
// 정규식 없이 선형 시간이다. 애매하면 링크로 본다: 닫히지 않은 구문은 끝까지 칠하고, 주소 run 은 ASCII 공백과
// 마크다운 링크 글자 경계에서만 끊는다(링크 글자 "[T](주소)" 의 T 는 따로 판정해 주소 모양이 아니면 통과).
[[nodiscard]] std::vector<LinkContext> classify_link_contexts(std::string_view response,
                                                              std::span<const TokenOccurrence> tokens);

// token 하나라도 링크 문맥이면 ResponseTokenInLink. 어떤 token 인지는 감사에만 남긴다.
[[nodiscard]] std::expected<void, Rejection> check_link_contexts(std::string_view response,
                                                                 std::span<const TokenOccurrence> tokens);

}  // namespace prompt_airlock::core
