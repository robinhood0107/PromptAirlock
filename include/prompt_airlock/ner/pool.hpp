// NER 추론 worker pool(Phase 7-2). 고정 수의 worker 와 유한 대기열로 추론을 묶는다.
// 요청마다 스레드를 만들지 않고, 대기열이 차면 기다리지 않고 Overloaded, 결과가 늦으면 Timeout 으로 거절한다(fail closed).
#pragma once

#include <chrono>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <memory>
#include <stop_token>
#include <thread>
#include <vector>

#include "prompt_airlock/core/error.hpp"
#include "prompt_airlock/detect/ner_scanner.hpp"

namespace prompt_airlock::ner {

// worker 마다 세션 하나(약 105 MB, Phase 2 측정). 두 개면 약 210 MB.
inline constexpr std::size_t ner_workers = 2;
// 기다리는 일의 최대 수. 실행 중인 일은 세지 않는다.
inline constexpr std::size_t ner_queue_depth = 16;
// 요청 하나가 NER 결과를 기다리는 최대 시간. 가장 큰 일(창 128개)이 256 token p95 32 ms(Phase 2) 기준 약 4.1 초라
// 그 두 배 남짓으로 잡았다. 넘으면 Timeout. 요청 전체의 시간 상한은 호출자가 취소 신호로 건다(Phase 9-2).
inline constexpr std::chrono::milliseconds ner_wait_limit{10'000};

// worker 하나가 맡는 추론. 제품은 NerEngine 을 감싼 것이고, 시험은 가짜를 넣는다.
// 한 worker 는 한 스레드에서만 불린다. stop 이 켜지면 결과를 기다리는 요청이 이미 떠난 것이라 일찍 끝내도 된다.
class NerWorker {
public:
    NerWorker() = default;
    NerWorker(const NerWorker&) = delete;
    NerWorker& operator=(const NerWorker&) = delete;
    virtual ~NerWorker() = default;

    [[nodiscard]] virtual std::expected<std::vector<core::EntitySpan>, core::DetectError> run(
        std::string_view text, core::SegmentIndex segment, const detect::DetectionView& view, std::stop_token stop) = 0;
};

class NerPool final : public detect::NerScanner {
    struct Key {};  // 조립 함수 밖에서 생성자를 부르지 못하게 하는 열쇠

public:
    // dir 의 모델 파일을 한 번 읽어 확인하고 worker 마다 엔진을 만든다. 하나라도 실패하면 Unavailable.
    // 제품은 이 함수와 위 기본값만 쓴다.
    [[nodiscard]] static std::expected<std::shared_ptr<NerPool>, core::DetectError> make(
        const std::filesystem::path& dir);

    // 이미 만든 worker 로 pool 을 띄운다(make 와 시험이 쓴다). worker 가 없거나 깊이가 0 이면 Unavailable.
    [[nodiscard]] static std::expected<std::shared_ptr<NerPool>, core::DetectError> start(
        std::vector<std::unique_ptr<NerWorker>> workers, std::size_t queue_depth = ner_queue_depth,
        std::chrono::milliseconds wait_limit = ner_wait_limit);

    NerPool(Key, std::vector<std::unique_ptr<NerWorker>> workers, std::size_t queue_depth,
            std::chrono::milliseconds wait_limit);
    NerPool(const NerPool&) = delete;
    NerPool& operator=(const NerPool&) = delete;
    // 남은 일은 Unavailable 로 끝내고 worker 를 모두 기다린다.
    ~NerPool() override;

    // 장애·예외는 Unavailable, 대기열 포화와 창 수 초과는 Overloaded, wait_limit 초과와 stop 은 Timeout.
    // 기다리다 떠나면 그 일은 대기열에서 빼거나, 이미 돌고 있으면 worker 에 멈추라고 알린다.
    [[nodiscard]] std::expected<std::vector<core::EntitySpan>, core::DetectError> scan(
        std::string_view text, core::SegmentIndex segment, const detect::DetectionView& view,
        std::stop_token stop) const override;

    // 지금 기다리는 일의 수(실행 중 제외). 측정과 시험용.
    [[nodiscard]] std::size_t waiting() const;

private:
    struct State;
    void work(NerWorker& worker);

    std::unique_ptr<State> state_;
    std::vector<std::unique_ptr<NerWorker>> workers_;
    std::vector<std::thread> threads_;
};

}  // namespace prompt_airlock::ner
