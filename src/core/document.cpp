#include "prompt_airlock/core/document.hpp"

#include <utility>

#include "prompt_airlock/core/utf8.hpp"
#include "state_access.hpp"

namespace prompt_airlock::core {

PromptDocument::PromptDocument(detail::StateKey<PromptDocument>, std::vector<Segment> segments,
                               std::vector<ContentForm> forms) noexcept
    : segments_(std::move(segments)), forms_(std::move(forms)) {}

std::size_t PromptDocument::total_bytes() const noexcept {
    std::size_t total = 0;
    for (const auto& segment : segments_) {
        total += segment.text().size();
    }
    return total;
}

ContentForm PromptDocument::content_form(std::uint32_t message) const noexcept {
    return message < forms_.size() ? forms_[message] : ContentForm::String;
}

PromptDocumentBuilder& PromptDocumentBuilder::add_message(MessageRole role, ContentForm form,
                                                          std::vector<SensitiveText> parts) & {
    messages_.push_back(Message{role, form, std::move(parts)});
    return *this;
}

PromptDocumentBuilder& PromptDocumentBuilder::add_stop(SensitiveText stop) & {
    stops_.push_back(std::move(stop));
    return *this;
}

std::expected<PromptDocument, InputError> PromptDocumentBuilder::build() && {
    if (messages_.empty()) {
        return std::unexpected(InputError::EmptyDocument);
    }
    std::size_t total = 0;
    auto accept = [&total](const SensitiveText& text) -> std::expected<void, InputError> {
        if (const auto valid = validate_utf8(text.view()); !valid) {
            return std::unexpected(valid.error());
        }
        total += text.size();
        if (total > max_prompt_bytes) {
            return std::unexpected(InputError::TooLarge);
        }
        return {};
    };

    std::vector<Segment> segments;
    std::vector<ContentForm> forms;
    forms.reserve(messages_.size());
    for (std::uint32_t m = 0; m < messages_.size(); ++m) {
        auto& message = messages_[m];
        const bool shape_ok = message.form == ContentForm::String ? message.parts.size() == 1 : !message.parts.empty();
        if (!shape_ok) {
            return std::unexpected(InputError::EmptyContent);
        }
        forms.push_back(message.form);
        for (std::uint32_t p = 0; p < message.parts.size(); ++p) {
            if (const auto ok = accept(message.parts[p]); !ok) {
                return std::unexpected(ok.error());
            }
            segments.emplace_back(MessageSource{message.role, m, p}, std::move(message.parts[p]));
        }
    }
    for (std::uint32_t s = 0; s < stops_.size(); ++s) {
        if (const auto ok = accept(stops_[s]); !ok) {
            return std::unexpected(ok.error());
        }
        segments.emplace_back(StopSource{s}, std::move(stops_[s]));
    }
    return PromptDocument(detail::StateAccess::key<PromptDocument>(), std::move(segments), std::move(forms));
}

}  // namespace prompt_airlock::core
