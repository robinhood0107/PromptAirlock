// 게이트웨이 설정. 설정 파일(JSON) 하나를 읽어 검증한 뒤 바꾸지 않는 snapshot 으로 쓴다.
// 하나라도 틀리면 기동하지 않는다. 모르는 키도 오류다(오타가 조용히 무시되지 않게).
#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "prompt_airlock/core/request_params.hpp"
#include "prompt_airlock/core/types.hpp"

namespace prompt_airlock::gateway {

struct ListenConfig {
    std::string address;  // IP 주소만(호스트 이름 거절)
    std::uint16_t port = 0;
    std::filesystem::path certificate_chain;
    std::filesystem::path private_key;
};

struct ProviderConfig {
    std::string host;
    std::uint16_t port = 443;
    std::string target;  // 경로. 예: /v1/chat/completions
    std::filesystem::path credential_file;
    std::filesystem::path trust_file;  // 비면 운영체제 기본 신뢰 저장소
    std::string model;
};

// 허용 출처(ADR 0013, 0020). token 원문은 두지 않고 SHA-256 만 둔다.
struct Origin {
    std::string name;
    std::string token_sha256;  // 소문자 16진수 64자
    core::GradePolicy grade_policy = core::GradePolicy::Declare;
};

struct Config {
    ListenConfig listen;
    ProviderConfig provider;
    std::vector<Origin> origins;
    std::vector<std::string> internal_terms;  // 기관 보호어: 자기 기관·계열사·거래처 이름
    core::OutputTokenCap output_token_cap = core::OutputTokenCap::standard();
    int history_retention_days = 365;  // 감사·이력 보존 기간, 365 이상(ADR 0021)
    bool sentence_warn = false;        // 문장 판별기 경고 모드(ADR 0023). 켜면 모델을 불러오지 못할 때 기동하지 않는다
};

enum class ConfigProblem : std::uint8_t {
    NotJson,
    UnknownKey,
    Missing,
    WrongType,
    InvalidValue,
    Duplicate,
};

// 어디가 틀렸는지 운영자에게 알려 주는 오류. field 는 "provider.url", "origins[1].name" 같은 경로다.
struct ConfigError {
    ConfigProblem problem;
    std::string field;
};

// 상대 경로는 base_dir(보통 설정 파일이 있는 폴더) 기준으로 바꾼다. 파일 존재 여부는 여기서 보지 않는다.
[[nodiscard]] std::expected<Config, ConfigError> parse_config(std::string_view json_text,
                                                              const std::filesystem::path& base_dir);

[[nodiscard]] std::string_view config_problem_name(ConfigProblem problem) noexcept;

}  // namespace prompt_airlock::gateway
