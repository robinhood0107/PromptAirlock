// 문서 파일에서 뽑은 글자(ADR 0028). 추출 실행 파일 안에서만 파일 byte 를 해석하고, 게이트웨이는 이 결과만 받는다.
// 원문 값(글자)을 담으므로 감사 기록에는 형식·개수만 남긴다.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace prompt_airlock::extract {

enum class DocumentFormat : std::uint8_t { Text, Csv, Markdown, Html, Docx, Xlsx, Pptx, Hwpx, Hwpml, Hwp, Pdf, Zip };

enum class ExtractError : std::uint8_t {
    TooLarge,        // 파일·풀린 크기·출력이 상한을 넘음
    UnknownFormat,   // 판별할 수 없는 byte
    LegacyFormat,    // doc·xls·ppt 같은 옛 형식(새 형식으로 저장해 달라고 안내)
    Unsupported,     // 알지만 아직 받지 않는 형식
    Encrypted,       // 암호·DRM
    Damaged,         // 잘림, 구조 오류
    Bomb,            // 압축률·항목 수·깊이 상한 초과
    NoText,          // 뽑을 글자가 없음
};

// 보내지 않고 세기만 한 부분(전송 최소화). 응답에서 사용자에게 개수를 알린다.
struct Omitted {
    std::uint32_t comments = 0;   // 메모·주석
    std::uint32_t revisions = 0;  // 변경 추적의 지운 글
    std::uint32_t hidden = 0;     // 숨긴 시트·행·슬라이드
    std::uint32_t other_parts = 0;  // 머리글·바닥글·노트처럼 본문이 아닌 부분, 해석하지 않은 zip 항목
    bool operator==(const Omitted&) const noexcept = default;
};

// 위치가 붙은 글자 덩어리. where 는 "p3", "Sheet1!12", "slide2", "a.zip/b.docx:p4" 같은 사람이 읽는 위치다.
struct TextBlock {
    std::string where;
    std::string text;  // UTF-8
    bool operator==(const TextBlock&) const noexcept = default;
};

struct ExtractedDocument {
    DocumentFormat format = DocumentFormat::Text;
    std::vector<TextBlock> blocks;
    Omitted omitted;
};

// 고정 상한(#226 댓글에 측정 전 고정). 시험만 더 작은 값을 쓴다.
struct ExtractLimits {
    std::size_t file_bytes = 32U << 20;
    std::size_t zip_entries = 1000;
    std::size_t entry_bytes = 64U << 20;
    std::size_t total_bytes = 128U << 20;  // 파일 하나에서 풀린 크기 합(안의 zip 포함)
    std::size_t ratio = 100;               // 항목 하나의 풀린 크기 / 압축 크기
    std::size_t depth = 2;                 // zip 안 문서까지
    std::size_t nested_documents = 64;
    std::size_t xml_depth = 256;
    std::size_t output_bytes = 8U << 20;   // 뽑은 글자 합
    std::size_t pdf_pages = 2000;
};

// name_hint 는 파일 이름의 확장자(소문자, 점 없이, 비어도 됨). 글자 형식(txt·csv·md·htm)을 가릴 때만 쓴다.
[[nodiscard]] std::expected<ExtractedDocument, ExtractError> extract(std::span<const std::byte> file,
                                                                    std::string_view name_hint,
                                                                    const ExtractLimits& limits = {});

[[nodiscard]] std::string_view format_name(DocumentFormat format) noexcept;
[[nodiscard]] std::string_view error_name(ExtractError error) noexcept;

}  // namespace prompt_airlock::extract
