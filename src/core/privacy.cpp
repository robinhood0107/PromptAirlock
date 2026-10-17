#include "prompt_airlock/core/privacy.hpp"

#include <algorithm>
#include <map>
#include <string>

#include "state_access.hpp"

namespace prompt_airlock::core {
namespace {

constexpr std::size_t leak_window = 4;

[[nodiscard]] constexpr char ascii_upper(char c) noexcept { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c; }

// R 에 원문의 연속 4자(원문이 더 짧으면 원문 전체)가 ASCII 대소문자 무시로 나타나는가(ADR 0008).
[[nodiscard]] bool random_part_leaks(std::string_view random, std::string_view value) noexcept {
    const auto width = std::min(value.size(), leak_window);
    if (width == 0 || width > random.size()) {
        return false;
    }
    for (std::size_t v = 0; v + width <= value.size(); ++v) {
        for (std::size_t r = 0; r + width <= random.size(); ++r) {
            if (std::equal(random.begin() + r, random.begin() + r + width, value.begin() + v,
                           [](char a, char b) { return ascii_upper(a) == ascii_upper(b); })) {
                return true;
            }
        }
    }
    return false;
}

[[nodiscard]] std::expected<void, ProtectionError> check_tokens(std::span<const ProtectionTarget> targets,
                                                                std::span<const Segment> segments,
                                                                std::span<const Token> tokens) {
    if (tokens.size() != targets.size()) {
        return std::unexpected(ProtectionError::CountMismatch);
    }
    std::map<std::pair<EntityType, std::string_view>, std::string_view> token_of_value;
    std::map<std::string_view, std::pair<EntityType, std::string_view>> value_of_token;
    for (std::size_t i = 0; i < targets.size(); ++i) {
        const auto& target = targets[i];
        const auto& token = tokens[i];
        if (token.label_type() != target.label_type) {
            return std::unexpected(ProtectionError::LabelMismatch);
        }
        const auto value =
            segments[target.segment.value()].text().substr(target.span.begin().value(), target.span.size());
        if (random_part_leaks(token.random_part(), value)) {
            return std::unexpected(ProtectionError::TokenLeaksValue);
        }
        const auto key = std::pair{target.label_type, value};
        const auto [by_value, new_value] = token_of_value.try_emplace(key, token.text());
        const auto [by_token, new_token] = value_of_token.try_emplace(token.text(), key);
        if (by_value->second != token.text() || by_token->second != key) {
            return std::unexpected(ProtectionError::InconsistentAssignment);
        }
    }
    return {};
}

}  // namespace

std::vector<ProtectionTarget> protection_targets(const PolicyCheckedPrompt& prompt) {
    std::vector<ProtectionTarget> out;
    for (const auto& entity : prompt.entities()) {
        if (entity.action == Action::Tokenize) {
            out.push_back(ProtectionTarget{entity.segment, entity.span, entity.label_type});
        }
    }
    return out;
}

std::expected<ProtectedPrompt, Rejection> apply_protection(PolicyCheckedPrompt prompt, std::vector<Token> tokens) {
    const auto strategy = prompt.strategy().kind();
    const auto& document = prompt.document();
    const auto segments = document.segments();
    auto targets = protection_targets(prompt);
    if (strategy == PrivacyStrategyKind::UniquePseudonym) {
        if (const auto checked = check_tokens(targets, segments, tokens); !checked) {
            return std::unexpected(Rejection::from_error(checked.error()));
        }
    } else if (!tokens.empty()) {
        return std::unexpected(Rejection::from_error(ProtectionError::CountMismatch));
    }
    if (strategy == PrivacyStrategyKind::NoProtection) {
        targets.clear();
        tokens.clear();
    }

    const auto replacement_text = [&](std::size_t i) -> std::string {
        switch (strategy) {
            case PrivacyStrategyKind::UniquePseudonym: return std::string(tokens[i].text());
            case PrivacyStrategyKind::Redaction: return std::string(token_open) + "REDACTED" + std::string(token_close);
            case PrivacyStrategyKind::TypeMask:
                return std::string(token_open) + std::string(entity_type_name(targets[i].label_type)) +
                       std::string(token_close);
            case PrivacyStrategyKind::NoProtection: break;
        }
        return {};
    };

    std::vector<Segment> rewritten;
    rewritten.reserve(segments.size());
    std::vector<Replacement> replacements;
    replacements.reserve(targets.size());
    std::size_t next = 0;
    for (std::uint32_t s = 0; s < segments.size(); ++s) {
        const auto text = segments[s].text();
        std::string out;
        out.reserve(text.size());
        std::size_t copied = 0;
        for (; next < targets.size() && targets[next].segment.value() == s; ++next) {
            const auto& target = targets[next];
            out.append(text.substr(copied, target.span.begin().value() - copied));
            const auto begin = out.size();
            out.append(replacement_text(next));
            replacements.push_back(Replacement{
                target.segment, *ByteSpan::make(Utf8ByteOffset{begin}, Utf8ByteOffset{out.size()}), target.label_type});
            copied = target.span.end().value();
        }
        out.append(text.substr(copied));
        rewritten.emplace_back(segments[s].source(), SensitiveText(std::move(out)));
    }

    std::vector<ContentForm> forms;
    forms.reserve(document.message_count());
    for (std::uint32_t m = 0; m < document.message_count(); ++m) {
        forms.push_back(document.content_form(m));
    }
    // 보호 후 텍스트는 token 이 원문보다 길 수 있어 64 KiB 를 다시 재지 않는다(입력 한도는 원문 기준).
    PromptDocument protected_document(detail::StateAccess::key<PromptDocument>(), std::move(rewritten),
                                      std::move(forms));
    return ProtectedPrompt(detail::StateAccess::key<ProtectedPrompt>(), std::move(protected_document),
                           prompt.params(), prompt.grade(), std::move(replacements));
}

}  // namespace prompt_airlock::core
