#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "prompt_airlock/core/detail/attributes.hpp"
#include "prompt_airlock/core/detail/state_key.hpp"
#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/core/sensitive.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::core {

// 메시지 content 의 원래 모양. 문자열 하나인지, text part 배열인지(ADR 0017).
enum class ContentForm : std::uint8_t { String, TextParts };

// segment 가 온 곳. 메시지의 몇 번째 part 이거나, 몇 번째 stop 문자열이다.
struct MessageSource {
    MessageRole role;
    std::uint32_t message;
    std::uint32_t part;
    bool operator==(const MessageSource&) const noexcept = default;
};
struct StopSource {
    std::uint32_t index;
    bool operator==(const StopSource&) const noexcept = default;
};
using SegmentSource = std::variant<MessageSource, StopSource>;

// 검사 단위 텍스트 하나. 탐지 위치는 segment 텍스트 기준 UTF-8 byte 다.
class Segment {
public:
    Segment(SegmentSource source, SensitiveText text) noexcept : source_(source), text_(std::move(text)) {}
    Segment(const Segment&) = delete;
    Segment& operator=(const Segment&) = delete;
    Segment(Segment&&) noexcept = default;
    Segment& operator=(Segment&&) noexcept = default;
    ~Segment() = default;

    [[nodiscard]] SegmentSource source() const noexcept { return source_; }
    [[nodiscard]] std::string_view text() const& noexcept PA_LIFETIMEBOUND { return text_.view(); }
    std::string_view text() const&& = delete;

private:
    SegmentSource source_;
    SensitiveText text_;
};

// 검사 대상 묶음: 모든 역할의 메시지와 stop 문자열(ADR 0017). 메시지 segment 가 먼저, stop 이 뒤에 온다.
class PromptDocument {
public:
    PromptDocument(detail::StateKey<PromptDocument>, std::vector<Segment> segments,
                   std::vector<ContentForm> forms) noexcept;
    // std::vector 는 원소가 복사 불가여도 복사 가능하다고 답하므로 복사를 명시적으로 지운다.
    PromptDocument(const PromptDocument&) = delete;
    PromptDocument& operator=(const PromptDocument&) = delete;
    PromptDocument(PromptDocument&&) noexcept = default;
    PromptDocument& operator=(PromptDocument&&) noexcept = default;
    ~PromptDocument() = default;

    [[nodiscard]] std::span<const Segment> segments() const& noexcept PA_LIFETIMEBOUND { return segments_; }
    std::span<const Segment> segments() const&& = delete;
    [[nodiscard]] std::size_t total_bytes() const noexcept;
    [[nodiscard]] std::size_t message_count() const noexcept { return forms_.size(); }
    // 범위 밖이면 String 을 돌려준다. 호출하는 쪽은 segment 의 message 번호만 넘긴다.
    [[nodiscard]] ContentForm content_form(std::uint32_t message) const noexcept;

private:
    std::vector<Segment> segments_;
    std::vector<ContentForm> forms_;
};

// 바깥(JSON 경계)에서 받은 메시지와 stop 을 검사해 묶음을 만든다.
class PromptDocumentBuilder {
public:
    PromptDocumentBuilder& add_message(MessageRole role, ContentForm form, std::vector<SensitiveText> parts) &;
    PromptDocumentBuilder& add_stop(SensitiveText stop) &;
    // 메시지가 없으면 EmptyDocument, String 인데 part 가 1개가 아니거나 TextParts 인데 0개면 EmptyContent,
    // UTF-8 이 아니면 InvalidUtf8, 모든 segment 합이 max_prompt_bytes 를 넘으면 TooLarge.
    [[nodiscard]] std::expected<PromptDocument, InputError> build() &&;

private:
    struct Message {
        MessageRole role;
        ContentForm form;
        std::vector<SensitiveText> parts;
    };
    std::vector<Message> messages_;
    std::vector<SensitiveText> stops_;
};

}  // namespace prompt_airlock::core
