// 탐지용 보기(ADR 0007): UTF-8 검증 → 보이지 않는 글자(서식 문자 Cf, 탭·줄바꿈 밖의 제어 문자, U+FFFE/FFFF) 제거 → NFKC.
// 보기의 각 글자는 자신이 온 원문 byte 구간을 기억한다. 탐지 결과는 그 구간으로 되돌린다.
#pragma once

#include <cstdint>
#include <expected>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/offset.hpp"
#include "prompt_airlock/core/utf8.hpp"

namespace prompt_airlock::detect {

// units[i].source 는 원문 byte 구간이다. 정규화로 합쳐지거나 갈라진 글자는 함께 정규화한 구간 전체를 가리킨다.
struct DetectionView {
    std::vector<core::DecodedCodepoint> units;
};

// WithoutLatex 는 LaTeX 표기(명령, 중괄호, $, % 주석)를 더 지우고 ~ 를 빈칸으로 본 보기다(결정 #235).
// 번호·이메일 탐지만 이 보기에서 한 번 더 돌린다. 지운 글자의 원문 위치는 남으므로 치환은 명령까지 덮는다.
enum class ViewKind { Plain, WithoutLatex };

// 정규화 실패나 구간별 결과와 전체 결과의 불일치는 DetectError::Unavailable 이다(요청 거절, fail closed).
[[nodiscard]] std::expected<DetectionView, core::DetectError> make_view(std::string_view text,
                                                                     ViewKind kind = ViewKind::Plain);

// 보기 구간 [first, last] 를 원문 byte 구간으로 바꾼다. first <= last < units.size() 여야 한다.
[[nodiscard]] core::ByteSpan source_span(const DetectionView& view, std::uint32_t first, std::uint32_t last) noexcept;

}  // namespace prompt_airlock::detect
