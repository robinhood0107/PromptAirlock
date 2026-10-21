// NER tokenizer 는 바깥 글을 직접 자른다. 아무 바이트를 넣어도 죽지 않고, 결과가 [CLS] ... [SEP] 모양이며
// 토큰 위치가 입력 글자 안에서 앞으로만 나아가고, 토큰 수가 글자 수 + 2 를 넘지 않는지 본다.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "prompt_airlock/core/utf8.hpp"
#include "prompt_airlock/ner/model_files.hpp"
#include "prompt_airlock/ner/tokenizer.hpp"

namespace pc = prompt_airlock::core;
namespace pn = prompt_airlock::ner;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const auto tokenizer = [] {
        const auto files = pn::read_verified_model_files(PA_NER_MODEL_DIR);
        if (!files) {
            __builtin_trap();  // 모델 파일이 없으면 fuzz 를 돌릴 수 없다
        }
        return *pn::WordPieceTokenizer::parse(files->tokenizer);
    }();
    const auto units = pc::decode_utf8(std::string_view(reinterpret_cast<const char*>(data), size));
    if (!units) {
        return 0;
    }
    const auto tokens = tokenizer.encode(*units);
    if (tokens.size() < 2 || tokens.size() > units->size() + 2 || !tokens.front().special || !tokens.back().special) {
        __builtin_trap();
    }
    std::uint32_t next = 0;
    for (std::size_t i = 1; i + 1 < tokens.size(); ++i) {
        const auto& t = tokens[i];
        if (t.special || t.first_unit < next || t.first_unit > t.last_unit || t.last_unit >= units->size()) {
            __builtin_trap();
        }
        next = t.last_unit + 1;
    }
    return 0;
}
