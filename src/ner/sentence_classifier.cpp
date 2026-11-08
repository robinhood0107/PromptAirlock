#include "prompt_airlock/ner/sentence_classifier.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <exception>
#include <semaphore>
#include <utility>

#include "prompt_airlock/core/sha256.hpp"
#include "prompt_airlock/core/utf8.hpp"
#include "prompt_airlock/ner/model_files.hpp"
#include "prompt_airlock/ner/session.hpp"
#include "prompt_airlock/ner/tokenizer.hpp"

namespace prompt_airlock::ner {
namespace {

using json = nlohmann::json;

// 모델(float32 kcelectra 약 511 MB)을 받는 상한. 설정·tokenizer 는 기본 상한(100 MiB)을 쓴다.
constexpr std::uintmax_t max_model_bytes = 1024ULL * 1024 * 1024;

// 참조어 앞뒤 경계(tests/measure/sentence_measure.cpp 의 개인 조건 v2 와 같은 값). "그 분야", "이 분기" 를 잡지 않으려고
// 앞은 글 처음·공백·문장 부호, 뒤는 글 끝·공백·문장 부호·조사 첫 글자만 받는다.
constexpr std::string_view left_marks = " \n\t\"'(,.:[";
constexpr std::string_view right_marks = " \n\t\"'),.?!:;]";
constexpr std::array<std::string_view, 22> particles = {"은", "는", "이", "가", "을", "를", "의", "도", "한", "에", "께",
                                                        "랑", "하", "과", "와", "만", "들", "님", "네", "말", "쪽", "이랑"};

[[nodiscard]] std::string as_string(const std::vector<std::byte>& bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

}  // namespace

std::vector<std::string_view> split_sentences(std::string_view text) {
    std::vector<std::string_view> out;
    const auto keep = [&](std::size_t from, std::size_t to) {
        const auto piece = text.substr(from, to - from);
        if (piece.find_first_not_of(" \n") != std::string_view::npos) {
            out.push_back(piece);
        }
    };
    std::size_t start = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        const bool end = c == '.' || c == '?' || c == '!' || c == '\n';
        if (end && (i + 1 == text.size() || text[i + 1] == ' ' || text[i + 1] == '\n')) {
            keep(start, i + 1);
            start = i + 1;
        }
    }
    keep(start, text.size());
    return out;
}

struct SentenceClassifier::Impl {
    Impl(WordPieceTokenizer t, OrtSession s, std::vector<std::string> c, std::vector<float> th, std::size_t max,
         std::vector<std::string> m, std::vector<std::string> r)
        : tokenizer(std::move(t)),
          session(std::move(s)),
          categories(std::move(c)),
          thresholds(std::move(th)),
          max_tokens(max),
          markers(std::move(m)),
          references(std::move(r)) {}

    WordPieceTokenizer tokenizer;
    mutable OrtSession session;  // ORT 의 Run 은 여러 스레드가 함께 불러도 된다. 동시 수는 slots 로 묶는다.
    mutable std::counting_semaphore<sentence_concurrency> slots{sentence_concurrency};
    std::vector<std::string> categories;  // 마지막 확률 칸(None)은 범주가 아니다
    std::vector<float> thresholds;
    std::size_t max_tokens;
    std::vector<std::string> markers;
    std::vector<std::string> references;
};

SentenceClassifier::SentenceClassifier(Key, std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
SentenceClassifier::~SentenceClassifier() = default;

std::expected<std::shared_ptr<const SentenceClassifier>, SentenceError> SentenceClassifier::make(
    const std::filesystem::path& dir, int threads) {
    try {
        const auto settings_bytes = read_pinned_file(dir / "classifier.json", sentence_settings_sha256);
        if (!settings_bytes) {
            return std::unexpected(SentenceError::Unavailable);
        }
        const auto settings = json::parse(as_string(*settings_bytes));
        auto categories = settings.at("categories").get<std::vector<std::string>>();
        auto thresholds = settings.at("thresholds").get<std::vector<float>>();
        const auto max_tokens = settings.at("max_tokens").get<std::size_t>();
        if (settings.at("version").get<int>() != 1 || categories.empty() || thresholds.size() != categories.size() ||
            max_tokens < 3 || max_tokens > 512) {
            return std::unexpected(SentenceError::Unavailable);
        }
        const auto tokenizer_bytes = read_pinned_file(dir / "tokenizer.json", settings.at("tokenizer_sha256").get<std::string>());
        const auto model_bytes =
            read_pinned_file(dir / "model.onnx", settings.at("model_sha256").get<std::string>(), max_model_bytes);
        if (!tokenizer_bytes || !model_bytes) {
            return std::unexpected(SentenceError::Unavailable);
        }
        auto tokenizer = WordPieceTokenizer::parse(as_string(*tokenizer_bytes));
        auto env = OrtEnv::create();
        if (!tokenizer || !env) {
            return std::unexpected(SentenceError::Unavailable);
        }
        auto session = OrtSession::create(*env, *model_bytes, threads);
        if (!session) {
            return std::unexpected(SentenceError::Unavailable);
        }
        auto impl = std::make_unique<Impl>(std::move(*tokenizer), std::move(*session), std::move(categories),
                                           std::move(thresholds), max_tokens,
                                           settings.at("person_markers").get<std::vector<std::string>>(),
                                           settings.at("person_references").get<std::vector<std::string>>());
        auto made = std::make_shared<const SentenceClassifier>(Key{}, std::move(impl));
        // 범주 수가 모델 출력과 맞는지 한 번 돌려 확인한다(None 한 칸을 더해 같아야 한다).
        const auto probe = made->probabilities("확인");
        if (!probe || probe->size() != made->impl_->categories.size() + 1) {
            return std::unexpected(SentenceError::Unavailable);
        }
        return made;
    } catch (const std::exception&) {
        return std::unexpected(SentenceError::Unavailable);  // 설정 JSON 모양이 다르거나 메모리 부족
    }
}

std::expected<std::vector<float>, SentenceError> SentenceClassifier::probabilities(std::string_view sentence) const {
    try {
        const auto units = core::decode_utf8(sentence);
        if (!units) {
            return std::unexpected(SentenceError::Unavailable);
        }
        auto tokens = impl_->tokenizer.encode(*units);
        // HF truncation 과 같게 앞쪽 token 을 남기고 끝 [SEP] 은 지킨다.
        if (tokens.size() > impl_->max_tokens) {
            tokens.erase(tokens.begin() + static_cast<std::ptrdiff_t>(impl_->max_tokens) - 1, tokens.end() - 1);
        }
        std::vector<std::int64_t> ids;
        ids.reserve(tokens.size());
        for (const auto& t : tokens) {
            ids.push_back(t.id);
        }
        return infer_probabilities(ids);
    } catch (const std::exception&) {
        return std::unexpected(SentenceError::Unavailable);
    }
}

std::expected<std::vector<float>, SentenceError> SentenceClassifier::infer_probabilities(
    std::span<const std::int64_t> ids) const {
    try {
        const auto logits = impl_->session.run(ids);
        if (!logits || logits->length != 1) {
            return std::unexpected(SentenceError::Unavailable);
        }
        std::vector<float> p(logits->values.begin(), logits->values.end());
        const float top = *std::ranges::max_element(p);
        float sum = 0.0F;
        for (auto& v : p) {
            v = std::exp(v - top);
            sum += v;
        }
        for (auto& v : p) {
            v /= sum;
        }
        return p;
    } catch (const std::exception&) { return std::unexpected(SentenceError::Unavailable); }
}

// 측정용 확률의 truncation 계약은 유지하고, 실제 판정은 모든 창을 본다.
std::expected<std::optional<SentenceHit>, SentenceError> SentenceClassifier::classify_sentence_all(
    std::string_view sentence, bool personal, std::stop_token stop, SentenceScanStatistics* statistics) const {
    try {
        const auto units = core::decode_utf8(sentence);
        if (!units) return std::unexpected(SentenceError::Unavailable);
        const auto tokens = impl_->tokenizer.encode(*units);
        if (tokens.size() < 2) return std::unexpected(SentenceError::Unavailable);
        const auto body = std::span(tokens).subspan(1, tokens.size() - 2);
        if (statistics) statistics->tokens += body.size();
        const auto capacity = impl_->max_tokens - 2;
        const auto overlap = std::min<std::size_t>(32, capacity / 2);
        std::optional<SentenceHit> best;
        std::size_t covered = 0;
        for (std::size_t first = 0;; first += capacity - overlap) {
            if (stop.stop_requested()) return std::unexpected(SentenceError::Timeout);
            const auto end = std::min(first + capacity, body.size());
            std::vector<std::int64_t> ids{tokens.front().id};
            for (const auto& token : body.subspan(first, end - first)) ids.push_back(token.id);
            ids.push_back(tokens.back().id);
            const auto p = infer_probabilities(ids);
            if (!p || p->size() != impl_->categories.size() + 1) return std::unexpected(SentenceError::Unavailable);
            if (statistics) {
                ++statistics->windows;
                statistics->checked_tokens += end - covered;
            }
            covered = end;
            const auto top = std::max_element(p->begin(), p->begin() + static_cast<std::ptrdiff_t>(impl_->categories.size()));
            const auto pred = static_cast<std::size_t>(top - p->begin());
            // 창마다 기존 argmax·문턱·개인 조건을 먼저 적용한다. 다른 창의 미달 판정이 양성을 덮지 않는다.
            if ((personal || impl_->categories[pred] == "Credential") && *top >= impl_->thresholds[pred] &&
                (!best || *top > best->score)) best = SentenceHit{impl_->categories[pred], *top};
            if (end == body.size()) break;
        }
        return best;
    } catch (const std::exception&) {
        return std::unexpected(SentenceError::Unavailable);
    }
}

bool SentenceClassifier::refers_to_person(std::string_view text) const {
    if (std::ranges::any_of(impl_->markers, [&](const std::string& m) { return text.find(m) != std::string_view::npos; })) {
        return true;
    }
    for (const auto& ref : impl_->references) {
        for (auto at = text.find(ref); at != std::string_view::npos; at = text.find(ref, at + 1)) {
            const bool left = at == 0 || left_marks.find(text[at - 1]) != std::string_view::npos;
            const auto rest = text.substr(at + ref.size());
            const bool right = rest.empty() || right_marks.find(rest.front()) != std::string_view::npos ||
                               std::ranges::any_of(particles, [&](std::string_view p) { return rest.starts_with(p); });
            if (left && right) {
                return true;
            }
        }
    }
    return false;
}

std::expected<std::optional<SentenceHit>, SentenceError> SentenceClassifier::classify(std::string_view text,
                                                                                     bool named_person,
    std::stop_token stop, SentenceScanStatistics* statistics) const {
    if (statistics) *statistics = {};
    if (!impl_->slots.try_acquire_for(sentence_wait_limit)) {
        return std::unexpected(SentenceError::Overloaded);
    }
    struct Release {
        std::counting_semaphore<sentence_concurrency>& slots;
        ~Release() { slots.release(); }
    } release{impl_->slots};
    const bool personal = named_person || refers_to_person(text);
    std::optional<SentenceHit> best;
    for (const auto sentence : split_sentences(text)) {
        auto hit = classify_sentence_all(sentence, personal, stop, statistics);
        if (!hit) return std::unexpected(hit.error());
        if (*hit && (!best || (*hit)->score > best->score)) best = std::move(**hit);
    }
    return best;
}

}  // namespace prompt_airlock::ner
