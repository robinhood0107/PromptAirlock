#include "prompt_airlock/ner/model_files.hpp"

#include <fstream>
#include <string_view>
#include <system_error>

#include "prompt_airlock/ner/sha256.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

namespace prompt_airlock::ner {
namespace {

// 기대하는 파일은 모두 100 MiB 보다 작다. 이보다 크면 읽지 않고 다른 파일로 본다.
constexpr std::uintmax_t max_file_bytes = 100ULL * 1024 * 1024;

[[nodiscard]] std::expected<std::vector<std::byte>, ModelFilesError> read_checked(const std::filesystem::path& path,
                                                                               std::string_view want_sha256) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(ModelFilesError::Missing);
    }
    if (size > max_file_bytes) {
        return std::unexpected(ModelFilesError::Mismatch);
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::unexpected(ModelFilesError::Missing);
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (static_cast<std::size_t>(in.gcount()) != bytes.size()) {
        return std::unexpected(ModelFilesError::Missing);
    }
    if (sha256_hex(bytes) != want_sha256) {
        return std::unexpected(ModelFilesError::Mismatch);
    }
    return bytes;
}

[[nodiscard]] std::string to_string(const std::vector<std::byte>& bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

[[nodiscard]] std::filesystem::path executable_dir() {
    std::error_code ec;
#ifdef _WIN32
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const auto n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0) {
            break;
        }
        if (n < buf.size()) {
            buf.resize(n);
            return std::filesystem::path(buf).parent_path();
        }
        buf.resize(buf.size() * 2);
    }
#else
    const auto exe = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (!ec) {
        return exe.parent_path();
    }
#endif
    return std::filesystem::current_path(ec);
}

}  // namespace

std::expected<VerifiedModelFiles, ModelFilesError> read_verified_model_files(const std::filesystem::path& dir) {
    // 작은 파일부터 확인해 잘못된 디렉터리를 모델 전체를 읽기 전에 거른다.
    auto tokenizer = read_checked(dir / "tokenizer.json", tokenizer_sha256);
    if (!tokenizer) {
        return std::unexpected(tokenizer.error());
    }
    auto config = read_checked(dir / "config.json", config_sha256);
    if (!config) {
        return std::unexpected(config.error());
    }
    auto model = read_checked(dir / "model.onnx", model_sha256);
    if (!model) {
        return std::unexpected(model.error());
    }
    VerifiedModelFiles out;
    out.model = std::move(*model);
    out.tokenizer = to_string(*tokenizer);
    out.config = to_string(*config);
    return out;
}

std::filesystem::path default_model_dir() { return executable_dir() / model_relative_dir; }

}  // namespace prompt_airlock::ner
