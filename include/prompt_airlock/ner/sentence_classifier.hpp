// 문장 판별기(Phase 7.8-3, ADR 0023). 글을 문장으로 나눠 미세조정한 인코더(ONNX)로 범주 확률을 내고,
// 개인 조건 v2 가 있을 때만 범주 문턱값과 비교한다. 판정 방식은 training/sentence/common.py 의 Scorer 와 같다.
// 걸려도 차단하지 않고 사용자 확인을 받는 데 쓴다. 판별하지 못하면(오류, 포화, 시간 초과) 부른 쪽이 막는다.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace prompt_airlock::ner {

// classifier.json(training/sentence/export.py 출력)의 SHA-256. 이 파일이 모델·tokenizer 해시를 담는다.
// kcelectra / 합성+실제 / seed 1 / alpha 0.03(#185, #187).
inline constexpr const char* sentence_settings_sha256 = "9876ee496a78bbaa03f4c2f8e8294493a13a8094aeb0e1426226a2b32567d1fd";
// 한 세션을 함께 쓰는 동시 판별 수. 넘으면 sentence_wait_limit 까지 기다린 뒤 Overloaded.
inline constexpr std::ptrdiff_t sentence_concurrency = 2;
inline constexpr std::chrono::milliseconds sentence_wait_limit{10'000};
// 판별 하나가 쓰는 계산 스레드 수. 256 token p95 가 1개 189.9 ms, 2개 127.3 ms, 4개 85.6 ms(#187)라 예산 150 ms 안의 가장 작은 값.
inline constexpr int sentence_intra_threads = 2;

enum class SentenceError : std::uint8_t { Unavailable, Overloaded, Timeout };

struct SentenceHit {
    std::string category;  // classifier.json 의 범주 이름(Health, ..., Credential)
    float score;
};

// 문장 나누기: 마침표·물음표·느낌표·줄바꿈 뒤(다음이 공백·줄바꿈이거나 끝)에서 나누고 공백뿐인 조각은 버린다.
// 결과는 text 를 가리키므로 text 보다 오래 두지 않는다.
[[nodiscard]] std::vector<std::string_view> split_sentences(std::string_view text);

class SentenceClassifier {
    struct Impl;
    struct Key {};

public:
    // dir 의 classifier.json, tokenizer.json, model.onnx 를 해시로 확인하고 세션을 만든다. 하나라도 어긋나면 Unavailable.
    [[nodiscard]] static std::expected<std::shared_ptr<const SentenceClassifier>, SentenceError> make(
        const std::filesystem::path& dir, int threads = sentence_intra_threads);

    SentenceClassifier(Key, std::unique_ptr<Impl> impl) noexcept;
    SentenceClassifier(const SentenceClassifier&) = delete;
    SentenceClassifier& operator=(const SentenceClassifier&) = delete;
    ~SentenceClassifier();

    // text 는 검증된 UTF-8. named_person 은 NER 이 이 글에서 사람 이름을 찾았는지다.
    // 걸리면 범주와 점수, 아니면 nullopt. 스레드 안전하다.
    [[nodiscard]] std::expected<std::optional<SentenceHit>, SentenceError> classify(std::string_view text,
                                                                                   bool named_person,
                                                                                   std::stop_token stop = {}) const;

    // 문장 하나의 범주 확률(마지막이 None). 측정 도구가 Python 과 견줄 때 쓴다.
    [[nodiscard]] std::expected<std::vector<float>, SentenceError> probabilities(std::string_view sentence) const;

    // 개인 조건 v2: 개인 표지, 소유 표현 x 친족어, 가리키는 말 x 사람 명사, 3인칭 대명사(NER 사람은 부른 쪽이 준다).
    [[nodiscard]] bool refers_to_person(std::string_view text) const;

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace prompt_airlock::ner
