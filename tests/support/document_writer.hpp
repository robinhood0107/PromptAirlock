#pragma once

#include <gtest/gtest.h>
#include <zip.h>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

namespace pa_test::documents {

struct Entry {
    std::string name;
    std::string data;
    bool store = false;  // 압축하지 않음
};

// 메모리 zip 을 만든다.
inline std::string make_zip(const std::vector<Entry>& entries) {
    zip_error_t error;
    zip_error_init(&error);
    zip_source_t* buffer = zip_source_buffer_create(nullptr, 0, 0, &error);
    zip_source_keep(buffer);
    zip_t* archive = zip_open_from_source(buffer, ZIP_TRUNCATE, &error);
    EXPECT_NE(archive, nullptr);
    for (const auto& e : entries) {
        zip_source_t* src = zip_source_buffer(archive, e.data.data(), e.data.size(), 0);
        const auto index = zip_file_add(archive, e.name.c_str(), src, ZIP_FL_ENC_RAW);
        EXPECT_GE(index, 0);
        zip_set_file_compression(archive, static_cast<zip_uint64_t>(index), e.store ? ZIP_CM_STORE : ZIP_CM_DEFLATE, 0);
    }
    EXPECT_EQ(zip_close(archive), 0);
    zip_source_open(buffer);
    zip_source_seek(buffer, 0, SEEK_END);
    const auto size = zip_source_tell(buffer);
    zip_source_seek(buffer, 0, SEEK_SET);
    std::string out(static_cast<std::size_t>(size), '\0');
    zip_source_read(buffer, out.data(), static_cast<zip_uint64_t>(size));
    zip_source_close(buffer);
    zip_source_free(buffer);
    zip_error_fini(&error);
    return out;
}

inline const std::string w = R"(xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main")";

inline std::string docx(std::string body, std::vector<Entry> extra = {}) {
    extra.push_back({"[Content_Types].xml", "<Types/>"});
    extra.push_back({"word/document.xml", "<w:document " + w + "><w:body>" + body + "</w:body></w:document>"});
    return make_zip(extra);
}

inline std::string base64(std::string_view bytes) {
    constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < bytes.size(); i += 3) {
        const auto a = static_cast<unsigned char>(bytes[i]);
        const auto b = i + 1 < bytes.size() ? static_cast<unsigned char>(bytes[i + 1]) : 0;
        const auto c = i + 2 < bytes.size() ? static_cast<unsigned char>(bytes[i + 2]) : 0;
        out.push_back(alphabet[a >> 2]);
        out.push_back(alphabet[((a & 3U) << 4) | (b >> 4)]);
        out.push_back(i + 1 < bytes.size() ? alphabet[((b & 15U) << 2) | (c >> 6)] : '=');
        out.push_back(i + 2 < bytes.size() ? alphabet[c & 63U] : '=');
    }
    return out;
}

}  // namespace pa_test::documents
