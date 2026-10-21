#include "prompt_airlock/ner/pool.hpp"

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <exception>
#include <future>
#include <mutex>
#include <system_error>
#include <utility>

#include "prompt_airlock/core/sensitive.hpp"
#include "prompt_airlock/ner/engine.hpp"

namespace prompt_airlock::ner {
namespace {

namespace pc = core;

using Result = std::expected<std::vector<pc::EntitySpan>, pc::DetectError>;

// 엔진 오류를 탐지 오류로 바꾸는 유일한 자리. 창 수 초과는 입력이 너무 큰 것이라 과부하로 거절한다.
[[nodiscard]] pc::DetectError to_detect_error(NerError e) noexcept {
    switch (e) {
        case NerError::TooManyWindows:
            return pc::DetectError::Overloaded;
        case NerError::InvalidSpan:
            return pc::DetectError::InvalidSpan;
        case NerError::InputTooLong:  // detect_all 은 창으로 나누므로 생기지 않는다
        case NerError::Unavailable:
            break;
    }
    return pc::DetectError::Unavailable;
}

class EngineWorker final : public NerWorker {
public:
    explicit EngineWorker(NerEngine engine) : engine_(std::move(engine)) {}

    Result run(std::string_view text, pc::SegmentIndex segment, const detect::DetectionView& view) override {
        auto found = engine_.detect_all(text, segment, view);
        if (!found) {
            return std::unexpected(to_detect_error(found.error()));
        }
        return std::move(*found);
    }

private:
    NerEngine engine_;
};

// 일 하나. 요청이 시간 초과로 먼저 떠나도 worker 가 안전하게 쓰도록 글과 보기의 사본을 가진다.
// 글 사본은 SensitiveText 라 일이 끝나 사라질 때 지워진다.
struct Job {
    pc::SensitiveText text;
    pc::SegmentIndex segment;
    detect::DetectionView view;
    std::promise<Result> result;
};

}  // namespace

struct NerPool::State {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<std::shared_ptr<Job>> jobs;
    std::size_t depth = 0;
    std::chrono::milliseconds wait_limit{};
    bool stopping = false;
};

NerPool::NerPool(Key, std::vector<std::unique_ptr<NerWorker>> workers, std::size_t queue_depth,
                 std::chrono::milliseconds wait_limit)
    : state_(std::make_unique<State>()), workers_(std::move(workers)) {
    state_->depth = queue_depth;
    state_->wait_limit = wait_limit;
}

std::expected<std::shared_ptr<NerPool>, pc::DetectError> NerPool::make(const std::filesystem::path& dir) {
    std::vector<std::unique_ptr<NerWorker>> workers;
    {
        // 모델 바이트(약 54 MB)는 세션이 복사해 가므로 엔진을 다 만들면 이 블록을 나가며 바로 버린다.
        const auto files = read_verified_model_files(dir);
        auto env = OrtEnv::create();
        if (!files || !env) {
            return std::unexpected(pc::DetectError::Unavailable);
        }
        for (std::size_t i = 0; i < ner_workers; ++i) {
            auto engine = NerEngine::make(*files, *env);
            if (!engine) {
                return std::unexpected(engine.error());
            }
            workers.push_back(std::make_unique<EngineWorker>(std::move(*engine)));
        }
    }
    return start(std::move(workers));
}

std::expected<std::shared_ptr<NerPool>, pc::DetectError> NerPool::start(std::vector<std::unique_ptr<NerWorker>> workers,
                                                                          std::size_t queue_depth,
                                                                          std::chrono::milliseconds wait_limit) {
    if (workers.empty() || queue_depth == 0 ||
        std::ranges::any_of(workers, [](const auto& w) { return w == nullptr; })) {
        return std::unexpected(pc::DetectError::Unavailable);
    }
    auto pool = std::make_shared<NerPool>(Key{}, std::move(workers), queue_depth, wait_limit);
    try {
        pool->threads_.reserve(pool->workers_.size());
        for (auto& worker : pool->workers_) {
            pool->threads_.emplace_back([p = pool.get(), w = worker.get()] { p->work(*w); });
        }
    } catch (const std::system_error&) {
        return std::unexpected(pc::DetectError::Unavailable);  // 이미 띄운 worker 는 소멸자가 거둔다
    }
    return pool;
}

NerPool::~NerPool() {
    {
        std::lock_guard lock(state_->mutex);
        state_->stopping = true;
    }
    state_->ready.notify_all();
    for (auto& thread : threads_) {
        thread.join();
    }
    for (auto& job : state_->jobs) {
        job->result.set_value(std::unexpected(pc::DetectError::Unavailable));
    }
}

void NerPool::work(NerWorker& worker) {
    for (;;) {
        std::shared_ptr<Job> job;
        {
            std::unique_lock lock(state_->mutex);
            state_->ready.wait(lock, [&] { return state_->stopping || !state_->jobs.empty(); });
            if (state_->stopping) {
                return;  // 남은 일은 소멸자가 거절한다
            }
            job = std::move(state_->jobs.front());
            state_->jobs.pop_front();
        }
        Result found = std::unexpected(pc::DetectError::Unavailable);
        try {
            found = worker.run(job->text.view(), job->segment, job->view);
        } catch (...) {
            // 예외가 worker 스레드를 빠져나가면 프로세스가 끝난다. 이 일만 실패로 돌려주고 worker 는 계속 돈다.
        }
        job->result.set_value(std::move(found));
    }
}

Result NerPool::scan(std::string_view text, pc::SegmentIndex segment, const detect::DetectionView& view) const {
    try {
        auto job = std::make_shared<Job>(Job{pc::SensitiveText::copy_of(text), segment, view, {}});
        auto result = job->result.get_future();
        {
            std::lock_guard lock(state_->mutex);
            if (state_->stopping) {
                return std::unexpected(pc::DetectError::Unavailable);
            }
            if (state_->jobs.size() >= state_->depth) {
                return std::unexpected(pc::DetectError::Overloaded);  // 기다리지 않는다
            }
            state_->jobs.push_back(job);
        }
        state_->ready.notify_one();
        if (result.wait_for(state_->wait_limit) == std::future_status::ready) {
            return result.get();
        }
        // 늦었다. 아직 대기열에 있으면 빼서 돌리지 않게 하고, 이미 돌고 있으면 결과를 버린다.
        {
            std::lock_guard lock(state_->mutex);
            std::erase(state_->jobs, job);
        }
        return std::unexpected(pc::DetectError::Timeout);
    } catch (const std::exception&) {
        return std::unexpected(pc::DetectError::Unavailable);  // 사본·대기열 메모리 부족 등
    }
}

std::size_t NerPool::waiting() const {
    std::lock_guard lock(state_->mutex);
    return state_->jobs.size();
}

}  // namespace prompt_airlock::ner
