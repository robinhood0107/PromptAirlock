// XML 스트림 해석(expat). 문서 형식 XML 은 DOCTYPE 를 쓰지 않으므로 DOCTYPE·개체 선언이 보이면 바로 멈춘다.
#include <expat.h>

#include <climits>
#include <memory>
#include <vector>

#include "detail.hpp"

namespace prompt_airlock::extract::detail {
namespace {

struct ParserDeleter {
    void operator()(XML_ParserStruct* p) const noexcept { XML_ParserFree(p); }
};

struct State {
    XML_Parser parser;
    const XmlHandler& handler;
    std::size_t max_depth;
    bool allow_simple_entities;
    std::size_t entities = 0;
    std::size_t depth = 0;
    ExtractError stopped_by = ExtractError::Damaged;
    bool stopped = false;
    std::vector<std::pair<std::string_view, std::string_view>> attrs;

    void stop(ExtractError why) {
        stopped = true;
        stopped_by = why;
        XML_StopParser(parser, XML_FALSE);
    }
};

[[nodiscard]] std::string_view local_name(const XML_Char* name) noexcept {
    const std::string_view s(name);
    const auto colon = s.rfind(':');
    return colon == std::string_view::npos ? s : s.substr(colon + 1);
}

void XMLCALL on_start(void* data, const XML_Char* name, const XML_Char** atts) {
    auto& st = *static_cast<State*>(data);
    if (++st.depth > st.max_depth) {
        st.stop(ExtractError::Bomb);
        return;
    }
    if (st.handler.start) {
        st.attrs.clear();
        for (std::size_t i = 0; atts[i] != nullptr && atts[i + 1] != nullptr; i += 2) {
            st.attrs.emplace_back(local_name(atts[i]), std::string_view(atts[i + 1]));
        }
        st.handler.start(local_name(name), st.attrs);
    }
}

void XMLCALL on_end(void* data, const XML_Char* name) {
    auto& st = *static_cast<State*>(data);
    --st.depth;
    if (st.handler.end) {
        st.handler.end(local_name(name));
    }
}

void XMLCALL on_text(void* data, const XML_Char* s, int len) {
    auto& st = *static_cast<State*>(data);
    if (st.handler.text) {
        st.handler.text(std::string_view(s, static_cast<std::size_t>(len)));
    }
}

void XMLCALL on_doctype(void* data, const XML_Char*, const XML_Char* sysid, const XML_Char* pubid, int) {
    auto& st = *static_cast<State*>(data);
    if (!st.allow_simple_entities || sysid != nullptr || pubid != nullptr) {
        st.stop(ExtractError::Damaged);  // 외부 DTD 는 어떤 경우에도 받지 않는다
    }
}

// 짧은 글자 값만 갖는 내부 개체(HWPML 의 nbsp 같은 것)만 받는다. 값에 다른 개체 참조·태그가 없으니 확장이 커질 수 없다.
void XMLCALL on_entity(void* data, const XML_Char*, int is_parameter, const XML_Char* value, int value_length,
                       const XML_Char*, const XML_Char* sysid, const XML_Char* pubid, const XML_Char*) {
    auto& st = *static_cast<State*>(data);
    const std::string_view v = value != nullptr ? std::string_view(value, static_cast<std::size_t>(value_length)) : "";
    if (!st.allow_simple_entities || is_parameter != 0 || value == nullptr || sysid != nullptr || pubid != nullptr ||
        v.size() > 32 || v.find_first_of("&<%") != std::string_view::npos || ++st.entities > 64) {
        st.stop(ExtractError::Damaged);
    }
}

}  // namespace

std::expected<void, ExtractError> parse_xml(std::string_view xml, const XmlHandler& handler, std::size_t max_depth,
                                            bool allow_simple_entities) {
    if (xml.size() > static_cast<std::size_t>(INT_MAX)) {
        return std::unexpected(ExtractError::TooLarge);
    }
    const std::unique_ptr<XML_ParserStruct, ParserDeleter> parser(XML_ParserCreate("UTF-8"));
    if (!parser) {
        return std::unexpected(ExtractError::Damaged);
    }
    State st{parser.get(), handler, max_depth, allow_simple_entities, 0, 0, ExtractError::Damaged, false, {}};
    XML_SetUserData(parser.get(), &st);
    XML_SetElementHandler(parser.get(), on_start, on_end);
    XML_SetCharacterDataHandler(parser.get(), on_text);
    XML_SetStartDoctypeDeclHandler(parser.get(), on_doctype);
    XML_SetEntityDeclHandler(parser.get(), on_entity);
    XML_SetParamEntityParsing(parser.get(), XML_PARAM_ENTITY_PARSING_NEVER);
    const auto status = XML_Parse(parser.get(), xml.data(), static_cast<int>(xml.size()), XML_TRUE);
    if (st.stopped) {
        return std::unexpected(st.stopped_by);
    }
    if (status != XML_STATUS_OK) {
        return std::unexpected(ExtractError::Damaged);
    }
    return {};
}

}  // namespace prompt_airlock::extract::detail
