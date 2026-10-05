#pragma once

#include <compare>
#include <cstddef>
#include <expected>

#include "prompt_airlock/core/error.hpp"

namespace prompt_airlock::core {

// 위치 종류마다 다른 타입을 만든다. Tag 가 다르면 비교·대입·변환이 컴파일되지 않는다(ADR 0007).
template <class Tag>
class Offset {
public:
    constexpr Offset() noexcept = default;
    constexpr explicit Offset(std::size_t value) noexcept : value_(value) {}

    [[nodiscard]] constexpr std::size_t value() const noexcept { return value_; }

    constexpr auto operator<=>(const Offset&) const noexcept = default;

private:
    std::size_t value_ = 0;
};

// 모듈 사이의 기준 위치: 원문 UTF-8 byte.
using Utf8ByteOffset = Offset<struct Utf8ByteTag>;
// 화면 표시용 코드포인트 위치.
using CodepointOffset = Offset<struct CodepointTag>;
// 모델 입력 시퀀스 안의 위치(Phase 7).
using TokenOffset = Offset<struct TokenTag>;

// 원문 UTF-8 byte 반열린 구간 [begin, end). 항상 begin < end 이다.
// 텍스트 안에 있는지와 문자 경계인지는 utf8.hpp 의 check_span 으로 확인한다.
class ByteSpan {
public:
    [[nodiscard]] static constexpr std::expected<ByteSpan, InputError> make(Utf8ByteOffset begin,
                                                                            Utf8ByteOffset end) noexcept {
        if (!(begin < end)) {
            return std::unexpected(InputError::EmptySpan);
        }
        return ByteSpan(begin, end);
    }

    // 두 구간을 모두 덮는 가장 작은 구간. 같은 텍스트의 유효한 구간끼리면 결과도 유효하다.
    [[nodiscard]] static constexpr ByteSpan hull(ByteSpan a, ByteSpan b) noexcept {
        return ByteSpan(a.begin_ < b.begin_ ? a.begin_ : b.begin_, a.end_ < b.end_ ? b.end_ : a.end_);
    }

    [[nodiscard]] constexpr Utf8ByteOffset begin() const noexcept { return begin_; }
    [[nodiscard]] constexpr Utf8ByteOffset end() const noexcept { return end_; }
    [[nodiscard]] constexpr std::size_t size() const noexcept { return end_.value() - begin_.value(); }

    [[nodiscard]] constexpr bool overlaps(ByteSpan other) const noexcept {
        return begin_ < other.end_ && other.begin_ < end_;
    }
    [[nodiscard]] constexpr bool contains(ByteSpan other) const noexcept {
        return begin_ <= other.begin_ && other.end_ <= end_;
    }

    constexpr auto operator<=>(const ByteSpan&) const noexcept = default;

private:
    constexpr ByteSpan(Utf8ByteOffset begin, Utf8ByteOffset end) noexcept : begin_(begin), end_(end) {}

    Utf8ByteOffset begin_;
    Utf8ByteOffset end_;
};

}  // namespace prompt_airlock::core
