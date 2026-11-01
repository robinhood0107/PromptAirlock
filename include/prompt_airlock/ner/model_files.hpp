// NER 모델·tokenizer·label 설정 파일. 고정된 커밋의 파일과 SHA-256 이 같을 때만 읽는다(ADR 0006).
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace prompt_airlock::ner {

// 실행 파일 기준 모델 디렉터리의 고정 상대 경로. 설정으로 바꿀 수 없다(ADR 0012).
inline constexpr const char* model_relative_dir = "models/ner";

// atonlee/koelectra-ko-pii-ner 커밋 1e75c01e 의 파일(onnx/model.onnx, tokenizer.json, config.json).
inline constexpr const char* model_sha256 = "7794bdaa2daaa524d1e7f5e4f80e6b62c6fe3bf36d7a9175f4cd4c011837ddc3";
inline constexpr const char* tokenizer_sha256 = "9bc85a2412ae3694bffac69cb152a9aafd59fd0357e540a343fa9daa62099c38";
inline constexpr const char* config_sha256 = "65b1c2e17c4eb6d4f5be29e4374784a03c7b886229af948757e55f3b79444a23";

enum class ModelFilesError : std::uint8_t { Missing, Mismatch };

// 해시를 확인한 바이트. 확인한 바이트를 그대로 써서 확인과 사용 사이에 파일이 바뀌어도 영향이 없다.
struct VerifiedModelFiles {
    std::vector<std::byte> model;
    std::string tokenizer;
    std::string config;
};

// path 를 읽어 SHA-256 이 want_sha256 과 같을 때만 바이트를 돌려준다. 없거나 읽을 수 없으면 Missing,
// max_bytes 보다 크거나 해시가 다르면 Mismatch(큰 파일은 읽지 않고 다른 파일로 본다).
[[nodiscard]] std::expected<std::vector<std::byte>, ModelFilesError> read_pinned_file(
    const std::filesystem::path& path, std::string_view want_sha256, std::uintmax_t max_bytes = 100ULL * 1024 * 1024);

// dir 안의 model.onnx, tokenizer.json, config.json 을 읽어 SHA-256 을 상수와 비교한다.
// 파일이 없거나 읽을 수 없으면 Missing, 해시가 다르면 Mismatch.
[[nodiscard]] std::expected<VerifiedModelFiles, ModelFilesError> read_verified_model_files(
    const std::filesystem::path& dir);

// 실행 파일 옆 models/ner. 실행 파일 위치를 알 수 없으면 현재 디렉터리 기준이다.
[[nodiscard]] std::filesystem::path default_model_dir();

}  // namespace prompt_airlock::ner
