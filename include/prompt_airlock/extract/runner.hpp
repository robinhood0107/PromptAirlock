// 추출 실행 파일을 자식 프로세스로 띄워 파일 byte 를 넘기고 결과를 받는다(ADR 0028). 게이트웨이 쪽에서 쓴다.
// 파일 해석은 자식 안에서만 일어나고, 이 쪽은 버전 붙은 JSON 만 읽는다. system() 은 쓰지 않는다.
// 시간 상한을 넘기거나 출력이 상한을 넘거나 부른 쪽이 취소하면 자식을 죽이고 실패를 돌려준다(fail closed).
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>

#include "prompt_airlock/extract/document.hpp"

namespace prompt_airlock::extract {

enum class RunError : std::uint8_t {
    StartFailed,     // 자식을 띄우지 못함
    Timeout,         // 시간 상한
    OutputTooLarge,  // 출력 상한
    Crashed,         // 0 이 아닌 종료(자기 제한에 걸린 경우 포함)
    BadOutput,       // 출력이 약속한 JSON 이 아님
    Cancelled,       // 부른 쪽 취소
};

struct RunLimits {
    std::chrono::milliseconds time{30000};
    std::size_t output_bytes = (8U << 20) + (2U << 20);  // 글자 상한 8 MiB + JSON 여유
};

// 자식이 해석에 실패하면(암호, 손상 등) 안쪽 expected 의 오류로 온다.
using ChildResult = std::expected<std::expected<ExtractedDocument, ExtractError>, RunError>;

// exe 는 prompt-airlock-extract 경로, name_hint 는 확장자(소문자, 점 없이, 영문·숫자만 넘긴다).
[[nodiscard]] ChildResult extract_in_child(const std::filesystem::path& exe, std::string_view name_hint,
                                           std::span<const std::byte> file, const RunLimits& limits = {},
                                           std::stop_token stop = {});

// 자식과 주고받는 형식(버전 1). 자식은 to_json 으로 쓰고 부모는 from_json 으로 읽는다.
inline constexpr int protocol_version = 1;
[[nodiscard]] std::string to_json(const std::expected<ExtractedDocument, ExtractError>& result);
[[nodiscard]] std::expected<std::expected<ExtractedDocument, ExtractError>, RunError> from_json(std::string_view json);

[[nodiscard]] std::string_view run_error_name(RunError error) noexcept;

}  // namespace prompt_airlock::extract
