// 메모리 zip(libzip, 압축은 저장·deflate 만). 항목 수, 항목 하나와 합의 풀린 크기, 압축률을 풀기 전에 보고,
// 풀면서도 적힌 크기보다 더 나오면 거절한다(크기를 속인 압축 폭탄).
#include <zip.h>

#include <algorithm>

#include "detail.hpp"

namespace prompt_airlock::extract::detail {

struct Zip::Impl {
    zip_t* archive = nullptr;
    std::vector<zip_uint64_t> index;  // names_ 와 같은 순서의 zip 안 번호
    ~Impl() {
        if (archive != nullptr) {
            zip_discard(archive);
        }
    }
};

Zip::Zip(std::unique_ptr<Impl> impl, std::vector<std::string> names)
    : impl_(std::move(impl)), names_(std::move(names)) {}
Zip::Zip(Zip&&) noexcept = default;
Zip& Zip::operator=(Zip&&) noexcept = default;
Zip::~Zip() = default;

std::expected<Zip, ExtractError> Zip::open(std::span<const std::byte> bytes, Context& context) {
    zip_error_t error;
    zip_error_init(&error);
    zip_source_t* source = zip_source_buffer_create(bytes.data(), bytes.size(), 0, &error);
    if (source == nullptr) {
        zip_error_fini(&error);
        return std::unexpected(ExtractError::Damaged);
    }
    auto impl = std::make_unique<Impl>();
    impl->archive = zip_open_from_source(source, ZIP_RDONLY | ZIP_CHECKCONS, &error);
    if (impl->archive == nullptr) {
        zip_source_free(source);
        const bool not_zip = zip_error_code_zip(&error) == ZIP_ER_NOZIP;
        zip_error_fini(&error);
        return std::unexpected(not_zip ? ExtractError::UnknownFormat : ExtractError::Damaged);
    }
    zip_error_fini(&error);
    const auto count = zip_get_num_entries(impl->archive, 0);
    if (count < 0) {
        return std::unexpected(ExtractError::Damaged);
    }
    if (static_cast<std::size_t>(count) > context.limits.zip_entries) {
        return std::unexpected(ExtractError::Bomb);
    }
    std::vector<std::string> names;
    for (zip_uint64_t i = 0; i < static_cast<zip_uint64_t>(count); ++i) {
        zip_stat_t st;
        if (zip_stat_index(impl->archive, i, 0, &st) != 0) {
            return std::unexpected(ExtractError::Damaged);
        }
        if ((st.valid & ZIP_STAT_ENCRYPTION_METHOD) != 0 && st.encryption_method != ZIP_EM_NONE) {
            return std::unexpected(ExtractError::Encrypted);
        }
        const char* raw = zip_get_name(impl->archive, i, ZIP_FL_ENC_RAW);
        if (raw == nullptr) {
            return std::unexpected(ExtractError::Damaged);
        }
        // 이름은 UTF-8 이 아니면 CP949 로 본다(한국어 Windows 압축 프로그램). 둘 다 아니면 번호로 부른다.
        std::string name(raw);
        if (!valid_utf8(name)) {
            auto decoded = cp949_to_utf8(name);
            name = decoded ? std::move(*decoded) : "entry" + std::to_string(i);
        }
        if (name.ends_with('/')) {
            continue;  // 폴더
        }
        names.push_back(std::move(name));
        impl->index.push_back(i);
    }
    return Zip(std::move(impl), std::move(names));
}

bool Zip::contains(std::string_view name) const { return std::ranges::find(names_, name) != names_.end(); }

std::expected<std::string, ExtractError> Zip::read(std::string_view name, Context& context) const {
    const auto it = std::ranges::find(names_, name);
    if (it == names_.end()) {
        return std::unexpected(ExtractError::Damaged);
    }
    const auto i = impl_->index[static_cast<std::size_t>(it - names_.begin())];
    zip_stat_t st;
    if (zip_stat_index(impl_->archive, i, 0, &st) != 0 || (st.valid & ZIP_STAT_SIZE) == 0 ||
        (st.valid & ZIP_STAT_COMP_SIZE) == 0 || (st.valid & ZIP_STAT_COMP_METHOD) == 0) {
        return std::unexpected(ExtractError::Damaged);
    }
    if (st.comp_method != ZIP_CM_STORE && st.comp_method != ZIP_CM_DEFLATE) {
        return std::unexpected(ExtractError::Unsupported);
    }
    const auto& limits = context.limits;
    if (st.size > limits.entry_bytes || context.unpacked + st.size > limits.total_bytes ||
        (st.size > 0 && st.comp_size == 0) || (st.comp_size > 0 && st.size / st.comp_size > limits.ratio)) {
        return std::unexpected(ExtractError::Bomb);
    }
    const std::unique_ptr<zip_file_t, int (*)(zip_file_t*)> file(zip_fopen_index(impl_->archive, i, 0), zip_fclose);
    if (!file) {
        return std::unexpected(ExtractError::Damaged);
    }
    std::string out(static_cast<std::size_t>(st.size), '\0');
    std::size_t got = 0;
    while (got < out.size()) {
        const auto n = zip_fread(file.get(), out.data() + got, out.size() - got);
        if (n <= 0) {
            return std::unexpected(ExtractError::Damaged);  // 잘림 또는 CRC 오류
        }
        got += static_cast<std::size_t>(n);
    }
    char extra = 0;
    if (zip_fread(file.get(), &extra, 1) != 0) {
        return std::unexpected(ExtractError::Bomb);  // 적힌 크기보다 더 풀림
    }
    context.unpacked += out.size();
    return out;
}

}  // namespace prompt_airlock::extract::detail
