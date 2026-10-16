#include "prompt_airlock/core/document.hpp"

#include <gtest/gtest.h>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace pc = prompt_airlock::core;
using pc::ContentForm;
using pc::MessageRole;

static_assert(!std::is_copy_constructible_v<pc::Segment>);
static_assert(!std::is_copy_constructible_v<pc::PromptDocument>);
static_assert(std::is_nothrow_move_constructible_v<pc::PromptDocument>);
static_assert(!std::is_constructible_v<pc::PromptDocument, std::vector<pc::Segment>, std::vector<ContentForm>>);

namespace {

std::vector<pc::SensitiveText> parts(std::initializer_list<std::string_view> texts) {
    std::vector<pc::SensitiveText> out;
    for (const auto t : texts) {
        out.push_back(pc::SensitiveText::copy_of(t));
    }
    return out;
}

}  // namespace

TEST(CoreDocument, AllRolesAndStopsBecomeSegments) {
    pc::PromptDocumentBuilder builder;
    builder.add_message(MessageRole::System, ContentForm::String, parts({"시스템 지시"}))
        .add_message(MessageRole::Developer, ContentForm::String, parts({"개발자 지시"}))
        .add_message(MessageRole::User, ContentForm::TextParts, parts({"첫 part", "둘째 part"}))
        .add_message(MessageRole::Model, ContentForm::String, parts({"이전 응답"}))
        .add_stop(pc::SensitiveText::copy_of("끝"));
    const auto doc = std::move(builder).build();
    ASSERT_TRUE(doc);

    const auto segments = doc->segments();
    ASSERT_EQ(segments.size(), 6U);
    EXPECT_EQ(std::get<pc::MessageSource>(segments[0].source()), (pc::MessageSource{MessageRole::System, 0, 0}));
    EXPECT_EQ(std::get<pc::MessageSource>(segments[3].source()), (pc::MessageSource{MessageRole::User, 2, 1}));
    EXPECT_EQ(segments[3].text(), "둘째 part");
    EXPECT_EQ(std::get<pc::MessageSource>(segments[4].source()), (pc::MessageSource{MessageRole::Model, 3, 0}));
    EXPECT_EQ(std::get<pc::StopSource>(segments[5].source()), (pc::StopSource{0}));
    EXPECT_EQ(doc->message_count(), 4U);
    EXPECT_EQ(doc->content_form(2), ContentForm::TextParts);
}

TEST(CoreDocument, RejectsMissingOrMalformedContent) {
    EXPECT_EQ(pc::PromptDocumentBuilder{}.build().error(), pc::InputError::EmptyDocument);

    pc::PromptDocumentBuilder only_stop;
    only_stop.add_stop(pc::SensitiveText::copy_of("끝"));
    EXPECT_EQ(std::move(only_stop).build().error(), pc::InputError::EmptyDocument);

    pc::PromptDocumentBuilder empty_parts;
    empty_parts.add_message(MessageRole::User, ContentForm::TextParts, {});
    EXPECT_EQ(std::move(empty_parts).build().error(), pc::InputError::EmptyContent);

    pc::PromptDocumentBuilder two_strings;
    two_strings.add_message(MessageRole::User, ContentForm::String, parts({"a", "b"}));
    EXPECT_EQ(std::move(two_strings).build().error(), pc::InputError::EmptyContent);
}

TEST(CoreDocument, RejectsInvalidUtf8InAnySegment) {
    pc::PromptDocumentBuilder in_stop;
    in_stop.add_message(MessageRole::User, ContentForm::String, parts({"정상"}))
        .add_stop(pc::SensitiveText(std::string("\xC0\x80")));
    EXPECT_EQ(std::move(in_stop).build().error(), pc::InputError::InvalidUtf8);
}

TEST(CoreDocument, SizeLimitCoversMessagesAndStops) {
    const auto half = pc::max_prompt_bytes / 2;
    pc::PromptDocumentBuilder exact;
    exact.add_message(MessageRole::User, ContentForm::String, parts({std::string(half, 'x')}))
        .add_stop(pc::SensitiveText(std::string(half, 'y')));
    const auto ok = std::move(exact).build();
    ASSERT_TRUE(ok);
    EXPECT_EQ(ok->total_bytes(), pc::max_prompt_bytes);

    pc::PromptDocumentBuilder over;
    over.add_message(MessageRole::User, ContentForm::String, parts({std::string(half, 'x')}))
        .add_stop(pc::SensitiveText(std::string(half + 1, 'y')));
    EXPECT_EQ(std::move(over).build().error(), pc::InputError::TooLarge);
}
