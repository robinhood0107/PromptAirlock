// 추출기 내부 공통(공개하지 않음).
#pragma once

#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "prompt_airlock/extract/document.hpp"

namespace prompt_airlock::extract::detail {

// 파일 하나를 해석하는 동안의 누적 상태. 안의 zip 을 풀 때도 같은 것을 넘겨 상한을 합으로 센다.
struct Context {
    const ExtractLimits& limits;
    ExtractedDocument& doc;
    std::size_t unpacked = 0;  // 풀린 byte 합
    std::size_t nested = 0;    // 안에 든 문서 수
    std::size_t output = 0;    // 뽑은 글자 byte 합
    std::string prefix;        // 안의 문서 위치 앞머리("a.zip/b.docx:")

    // 빈 글자는 버린다. 출력 상한을 넘으면 TooLarge.
    [[nodiscard]] std::expected<void, ExtractError> add(std::string where, std::string text);
};

// 글자 형식: BOM(UTF-8, UTF-16LE/BE) → 올바른 UTF-8 → CP949 순서로 본다. NUL 이 있으면 글자가 아니다.
[[nodiscard]] std::expected<std::string, ExtractError> decode_text(std::span<const std::byte> bytes);
// CP949 두 byte 글자를 UTF-8 로. 정의되지 않은 자리나 잘린 글자가 있으면 nullopt 대신 unexpected.
[[nodiscard]] std::expected<std::string, ExtractError> cp949_to_utf8(std::string_view bytes);
[[nodiscard]] bool valid_utf8(std::string_view s) noexcept;
void append_utf8(std::string& out, char32_t cp);

// 태그·script·style·주석을 빼고 문자 참조를 풀어 줄 단위로 나눈다.
[[nodiscard]] std::vector<std::string> html_lines(std::string_view html);

// XML 을 스트림으로 해석한다(expat). DOCTYPE·개체 선언이 있으면 Damaged(외부 개체·개체 확장 공격을 받지 않음).
// allow_simple_entities 면 외부 DTD 없는 짧은 글자 값 내부 개체만 받는다(HWPML).
// 중첩이 limits.xml_depth 를 넘으면 Bomb. 이름은 접두어를 뺀 지역 이름이다(w:t → t).
struct XmlHandler {
    std::function<void(std::string_view name, std::span<const std::pair<std::string_view, std::string_view>> attrs)> start;
    std::function<void(std::string_view name)> end;
    std::function<void(std::string_view text)> text;
};
[[nodiscard]] std::expected<void, ExtractError> parse_xml(std::string_view xml, const XmlHandler& handler,
                                                          std::size_t max_depth, bool allow_simple_entities = false);

// 메모리의 zip. 항목 수·압축률·풀린 크기를 상한으로 보고, 암호화·지원하지 않는 압축이면 거절한다.
class Zip {
public:
    [[nodiscard]] static std::expected<Zip, ExtractError> open(std::span<const std::byte> bytes, Context& context);
    Zip(Zip&&) noexcept;
    Zip& operator=(Zip&&) noexcept;
    Zip(const Zip&) = delete;
    Zip& operator=(const Zip&) = delete;
    ~Zip();

    [[nodiscard]] const std::vector<std::string>& names() const noexcept { return names_; }  // UTF-8, 순서는 zip 안 순서
    [[nodiscard]] bool contains(std::string_view name) const;
    // 이름이 없으면 Damaged. 풀린 byte 는 context.unpacked 에 더한다.
    [[nodiscard]] std::expected<std::string, ExtractError> read(std::string_view name, Context& context) const;

private:
    struct Impl;
    Zip(std::unique_ptr<Impl> impl, std::vector<std::string> names);
    std::unique_ptr<Impl> impl_;
    std::vector<std::string> names_;
};

[[nodiscard]] std::expected<void, ExtractError> extract_docx(const Zip& zip, Context& context);
[[nodiscard]] std::expected<void, ExtractError> extract_xlsx(const Zip& zip, Context& context);
[[nodiscard]] std::expected<void, ExtractError> extract_pptx(const Zip& zip, Context& context);
[[nodiscard]] std::expected<void, ExtractError> extract_hwpx(const Zip& zip, Context& context);
// 한글 XML(HWPML 2.x, 확장자 hwp 로 오기도 함). 이미 UTF-8 로 바꾼 글을 받는다.
[[nodiscard]] std::expected<void, ExtractError> extract_hwpml(std::string_view xml, Context& context);

// 판별 뒤 형식에 맞는 해석기를 부른다. 안의 문서도 이 함수로 다시 들어온다(depth 는 지금 깊이).
[[nodiscard]] std::expected<DocumentFormat, ExtractError> extract_into(std::span<const std::byte> file,
                                                                      std::string_view name_hint, std::size_t depth,
                                                                      Context& context);

// "word/document.xml" 의 숫자 붙은 이름을 숫자 순으로(slide2 < slide10).
[[nodiscard]] bool natural_less(std::string_view a, std::string_view b);

}  // namespace prompt_airlock::extract::detail
