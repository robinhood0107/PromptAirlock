#include "prompt_airlock/core/grade.hpp"

#include "state_access.hpp"

namespace prompt_airlock::core {

std::expected<DataGrade, InputError> parse_grade_mark(std::string_view mark) noexcept {
    if (mark == "C") {
        return DataGrade::Classified;
    }
    if (mark == "S") {
        return DataGrade::Sensitive;
    }
    if (mark == "O") {
        return DataGrade::Open;
    }
    return std::unexpected(InputError::ValueOutOfRange);
}

std::expected<OpenGrade, Rejection> resolve_grade(GradePolicy policy, std::span<const std::string_view> marks) noexcept {
    const auto unresolved = [] { return std::unexpected(Rejection::of(ReasonCode::GradeUnresolved)); };
    if (marks.empty()) {
        if (policy == GradePolicy::OOnly) {
            return OpenGrade(detail::StateAccess::key<OpenGrade>(), GradeOrigin::SourceDefault);
        }
        return unresolved();
    }
    if (marks.size() > 1) {
        return unresolved();
    }
    const auto grade = parse_grade_mark(marks.front());
    if (!grade) {
        return unresolved();
    }
    switch (*grade) {
        case DataGrade::Open: return OpenGrade(detail::StateAccess::key<OpenGrade>(), GradeOrigin::Header);
        case DataGrade::Classified: return std::unexpected(Rejection::of(ReasonCode::GradeClassified));
        case DataGrade::Sensitive: return std::unexpected(Rejection::of(ReasonCode::GradeSensitive));
    }
    return unresolved();
}

}  // namespace prompt_airlock::core
