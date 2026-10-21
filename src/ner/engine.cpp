#include "prompt_airlock/ner/engine.hpp"

#include <algorithm>
#include <cassert>
#include <charconv>
#include <nlohmann/json.hpp>
#include <span>
#include <string>

#include "prompt_airlock/ner/boundary.hpp"
#include "prompt_airlock/ner/windows.hpp"

namespace prompt_airlock::ner {
namespace {

namespace pc = core;

// config.json 의 id2label 을 읽는다. "O", "B-<종류>", "I-<종류>" 형식만 받는다.
// 이 모델에서 쓰는 종류는 NAME(사람)과 ORGANIZATION(기관)뿐이고 나머지는 O 처럼 본다.
[[nodiscard]] std::expected<std::vector<NerLabel>, pc::DetectError> parse_labels(const std::string& config_json) {
    try {
        const auto j = nlohmann::json::parse(config_json);
        const auto& id2label = j.at("id2label");
        std::vector<NerLabel> labels(id2label.size());
        std::vector<bool> seen(labels.size(), false);
        bool has_person = false;
        bool has_organization = false;
        for (const auto& [key, value] : id2label.items()) {
            std::size_t index = 0;
            const auto [end, ec] = std::from_chars(key.data(), key.data() + key.size(), index);
            if (ec != std::errc{} || end != key.data() + key.size() || index >= labels.size() || seen[index]) {
                return std::unexpected(pc::DetectError::Unavailable);
            }
            seen[index] = true;
            const auto name = value.get<std::string>();
            if (name == "O" || name.size() < 3 || name[1] != '-' || (name[0] != 'B' && name[0] != 'I')) {
                continue;
            }
            const auto kind = std::string_view(name).substr(2);
            if (kind == "NAME") {
                labels[index] = {pc::EntityType::Person, name[0] == 'B'};
                has_person = true;
            } else if (kind == "ORGANIZATION") {
                labels[index] = {pc::EntityType::Organization, name[0] == 'B'};
                has_organization = true;
            }
        }
        if (labels.empty() || !has_person || !has_organization) {
            return std::unexpected(pc::DetectError::Unavailable);
        }
        return labels;
    } catch (const nlohmann::json::exception&) {
        return std::unexpected(pc::DetectError::Unavailable);
    }
}

// 같은 종류의 연속 토큰을 묶은 보기 구간(양 끝 포함, 구간 안의 위치).
struct Run {
    pc::EntityType type;
    std::uint32_t first;
    std::uint32_t last;
    bool open;  // 다음 I 토큰이 이어 붙을 수 있다
};

}  // namespace

NerEngine::NerEngine(WordPieceTokenizer tokenizer, OrtSession session, std::vector<NerLabel> labels)
    : tokenizer_(std::move(tokenizer)), session_(std::move(session)), labels_(std::move(labels)) {}

std::expected<NerEngine, pc::DetectError> NerEngine::make(const std::filesystem::path& dir) {
    const auto files = read_verified_model_files(dir);
    auto env = OrtEnv::create();
    if (!files || !env) {
        return std::unexpected(pc::DetectError::Unavailable);
    }
    return make(*files, std::move(*env));
}

std::expected<NerEngine, pc::DetectError> NerEngine::make(const VerifiedModelFiles& files,
                                                          std::shared_ptr<const OrtEnv> env) {
    auto tokenizer = WordPieceTokenizer::parse(files.tokenizer);
    auto labels = parse_labels(files.config);
    if (!tokenizer || !labels) {
        return std::unexpected(pc::DetectError::Unavailable);
    }
    auto session = OrtSession::create(std::move(env), files.model);
    if (!session) {
        return std::unexpected(pc::DetectError::Unavailable);
    }
    return NerEngine(std::move(*tokenizer), std::move(*session), std::move(*labels));
}

std::expected<std::vector<pc::EntitySpan>, NerError> NerEngine::detect(std::string_view text, pc::SegmentIndex segment,
                                                                       const detect::DetectionView& view,
                                                                       ViewRange range) {
    if (range.first > range.end || range.end > view.units.size()) {
        return std::unexpected(NerError::InvalidSpan);
    }
    const auto tokens = tokenizer_.encode(std::span(view.units).subspan(range.first, range.end - range.first));
    if (tokens.size() > max_ner_tokens) {
        return std::unexpected(NerError::InputTooLong);  // 자르지 않는다
    }
    std::vector<pc::EntitySpan> out;
    const auto body = std::span(tokens).subspan(1, tokens.size() - 2);
    if (auto r = infer(text, segment, view, range.first, body, tokens.front().id, tokens.back().id, out); !r) {
        return std::unexpected(r.error());
    }
    return out;
}

std::expected<std::vector<pc::EntitySpan>, NerError> NerEngine::detect_all(std::string_view text,
                                                                           pc::SegmentIndex segment,
                                                                           const detect::DetectionView& view) {
    const auto tokens = tokenizer_.encode(view.units);
    const auto body = std::span(tokens).subspan(1, tokens.size() - 2);
    // 문장 끝: 토큰의 마지막 글자가 문장 부호이거나, 다음 토큰과의 사이에 줄바꿈이 있다.
    const auto is_stop = [](char32_t c) { return c == U'.' || c == U'?' || c == U'!' || c == U'\u3002'; };
    const auto is_newline = [](char32_t c) { return c == U'\n' || c == U'\r'; };
    std::vector<std::uint32_t> cuts;
    for (std::uint32_t i = 0; i + 1 < body.size(); ++i) {
        const auto gap = std::span(view.units).subspan(body[i].last_unit + 1, body[i + 1].first_unit - body[i].last_unit - 1);
        if (is_stop(view.units[body[i].last_unit].value) ||
            std::ranges::any_of(gap, [&](const auto& u) { return is_newline(u.value); })) {
            cuts.push_back(i);
        }
    }
    const auto windows = split_windows(static_cast<std::uint32_t>(body.size()), cuts);
    if (!windows) {
        return std::unexpected(NerError::TooManyWindows);
    }
    std::vector<pc::EntitySpan> out;
    for (const auto& w : *windows) {
        if (auto r = infer(text, segment, view, 0, body.subspan(w.first, w.end - w.first), tokens.front().id,
                           tokens.back().id, out);
            !r) {
            return std::unexpected(r.error());
        }
    }
    std::ranges::sort(out);
    const auto [first, last] = std::ranges::unique(out);
    out.erase(first, last);
    return out;
}

std::expected<void, NerError> NerEngine::infer(std::string_view text, pc::SegmentIndex segment,
                                               const detect::DetectionView& view, std::uint32_t base,
                                               std::span<const Token> body, std::int64_t cls, std::int64_t sep,
                                               std::vector<pc::EntitySpan>& out) {
    std::vector<std::int64_t> ids;
    ids.reserve(body.size() + 2);
    ids.push_back(cls);
    for (const auto& token : body) {
        ids.push_back(token.id);
    }
    ids.push_back(sep);
    assert(ids.size() <= max_ner_tokens);
    const auto logits = session_.run(ids);
    if (!logits || logits->labels != labels_.size()) {
        return std::unexpected(NerError::Unavailable);
    }

    // BIO 결합: B 는 새로 시작, I 는 같은 종류가 열려 있을 때만 잇고 아니면 새로 시작한다.
    // 같은 종류가 끊김 없이 맞닿으면(사이에 글자가 없으면) 하나로 합친다.
    std::vector<Run> runs;
    for (std::size_t i = 0; i < body.size(); ++i) {
        const auto& label = labels_[logits->argmax(i + 1)];  // 0 번은 앞 special
        if (!label.type) {
            if (!runs.empty()) {
                runs.back().open = false;
            }
            continue;
        }
        const auto first = body[i].first_unit;
        const auto last = body[i].last_unit;
        const bool joins = !runs.empty() && runs.back().type == *label.type &&
                           ((runs.back().open && !label.begin) || runs.back().last + 1 == first);
        if (joins) {
            runs.back().last = last;
            runs.back().open = true;
        } else {
            runs.push_back({*label.type, first, last, true});
        }
    }

    for (const auto& run : runs) {
        // 정답 규칙에 맞춘 경계(결정 #107): 어절로 넓힌 뒤 조사·호칭·직함·서술격 조사·법인 표기·부서명을 뗀다.
        const auto bytes = name_span(view, base + run.first, base + run.last, run.type);
        if (!bytes) {
            continue;  // 부호만 잡은 것은 이름이 아니다
        }
        const auto entity = pc::EntitySpan::make(text, segment, *bytes, run.type, pc::DetectorKind::Ner);
        if (!entity) {
            return std::unexpected(NerError::InvalidSpan);
        }
        out.push_back(*entity);
    }
    return {};
}

}  // namespace prompt_airlock::ner
