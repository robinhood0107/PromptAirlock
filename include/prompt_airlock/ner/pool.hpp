// NER 추론 worker pool(Phase 7-2). 고정 수의 worker 와 유한 대기열로 추론을 묶는다.
// 요청마다 스레드를 만들지 않고, 대기열이 차면 기다리지 않고 Overloaded 로 거절한다(fail closed).
#pragma once

#include <cstddef>
#include <expected>
#include <filesystem>
#include <memory>
#include <thread>
#include <vector>

#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/detect/ner_scanner.hpp"
#include "prompt_airlock/ner/engine.hpp"

namespace prompt_airlock::ner {

// worker 마다 세션 하나(약 105 MB, Phase 2 측정). 두 개면 약 210 MB.
inline constexpr std::size_t ner_workers = 2;
// 기다리는 일의 최대 수. 실행 중인 일은 세지 않는다.
inline constexpr std::size_t ner_queue_depth = 16;

class NerPool final : public detect::NerScanner {
    struct Key {};  // make 밖에서 생성자를 부르지 못하게 하는 열쇠

public:
    // dir 의 모델 파일을 한 번 읽어 확인하고 worker 마다 엔진을 만든다. 하나라도 실패하면 Unavailable.
    // workers, queue_depth 는 시험이 바꿔 보기 위한 값이고 제품은 기본값만 쓴다.
    [[nodiscard]] static std::expected<std::shared_ptr<NerPool>, core::DetectError> make(
        const std::filesystem::path& dir, std::size_t workers = ner_workers, std::size_t queue_depth = ner_queue_depth);

    NerPool(Key, std::vector<NerEngine> engines, std::size_t queue_depth);
    NerPool(const NerPool&) = delete;
    NerPool& operator=(const NerPool&) = delete;
    // 남은 일은 Unavailable 로 끝내고 worker 를 모두 기다린다.
    ~NerPool() override;

    [[nodiscard]] std::expected<std::vector<core::EntitySpan>, core::DetectError> scan(
        std::string_view text, core::SegmentIndex segment, const detect::DetectionView& view) const override;

private:
    struct State;
    void work(NerEngine& engine);

    std::unique_ptr<State> state_;
    std::vector<NerEngine> engines_;
    std::vector<std::thread> threads_;
};

}  // namespace prompt_airlock::ner
