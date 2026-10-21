// 모델 파일 확인: 맞는 파일은 읽고, 없거나 바이트가 다르면 거절한다.
#include "prompt_airlock/ner/model_files.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace pn = prompt_airlock::ner;
namespace fs = std::filesystem;

namespace {

const fs::path model_dir = PA_NER_MODEL_DIR;

// 시험마다 비어 있는 임시 디렉터리를 만들고 끝나면 지운다.
class TempDir {
public:
    TempDir() {
        path_ = fs::temp_directory_path() /
                (std::string("pa_ner_model_files_") + ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(path_);
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    [[nodiscard]] const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

void write(const fs::path& file, std::string_view content) {
    std::ofstream out(file, std::ios::binary);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

void copy_small_files(const fs::path& to) {
    fs::copy_file(model_dir / "tokenizer.json", to / "tokenizer.json");
    fs::copy_file(model_dir / "config.json", to / "config.json");
}

}  // namespace

TEST(NerModelFiles, BuildOutputMatchesThePinnedHashes) {
    const auto files = pn::read_verified_model_files(model_dir);
    ASSERT_TRUE(files);
    EXPECT_GT(files->model.size(), 50u * 1024 * 1024);
    EXPECT_FALSE(files->tokenizer.empty());
    EXPECT_FALSE(files->config.empty());
}

TEST(NerModelFiles, MissingDirectoryOrFileIsMissing) {
    TempDir tmp;
    EXPECT_EQ(pn::read_verified_model_files(tmp.path() / "none").error(), pn::ModelFilesError::Missing);
    EXPECT_EQ(pn::read_verified_model_files(tmp.path()).error(), pn::ModelFilesError::Missing);
    copy_small_files(tmp.path());
    EXPECT_EQ(pn::read_verified_model_files(tmp.path()).error(), pn::ModelFilesError::Missing);  // model.onnx 없음
}

TEST(NerModelFiles, ChangedTokenizerIsMismatch) {
    TempDir tmp;
    copy_small_files(tmp.path());
    write(tmp.path() / "tokenizer.json", "{}");
    EXPECT_EQ(pn::read_verified_model_files(tmp.path()).error(), pn::ModelFilesError::Mismatch);
}

TEST(NerModelFiles, OneChangedByteInConfigIsMismatch) {
    TempDir tmp;
    copy_small_files(tmp.path());
    std::fstream f(tmp.path() / "config.json", std::ios::in | std::ios::out | std::ios::binary);
    char c = 0;
    f.seekg(10);
    f.get(c);
    f.seekp(10);
    f.put(static_cast<char>(c ^ 1));
    f.close();
    EXPECT_EQ(pn::read_verified_model_files(tmp.path()).error(), pn::ModelFilesError::Mismatch);
}

TEST(NerModelFiles, ChangedModelIsMismatch) {
    TempDir tmp;
    copy_small_files(tmp.path());
    write(tmp.path() / "model.onnx", "not a model");
    EXPECT_EQ(pn::read_verified_model_files(tmp.path()).error(), pn::ModelFilesError::Mismatch);
}

TEST(NerModelFiles, DefaultDirIsFixedRelativeToTheExecutable) {
    const auto dir = pn::default_model_dir();
    EXPECT_TRUE(dir.is_absolute());
    EXPECT_EQ(dir.filename(), "ner");
    EXPECT_EQ(dir.parent_path().filename(), "models");
}
