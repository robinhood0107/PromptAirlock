#include "prompt_airlock/ner/pool.hpp"

#include <condition_variable>
#include <deque>
#include <future>
#include <mutex>
#include <optional>
#include <system_error>
#include <utility>

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

// 기다리는 일 하나. text 와 view 는 결과를 기다리는 요청 스레드가 가지고 있다.
struct Job {
    std::string_view text;
    pc::SegmentIndex segment;
    const detect::DetectionView* view;
    std::promise<Result> result;
};

}  // namespace

struct NerPool::State {
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<Job> jobs;
    std::size_t depth;
    bool stopping = false;
};

NerPool::NerPool(std::vector<NerEngine> engines, std::size_t queue_depth)
    : state_(std::make_unique<State>()), engines_(std::move(engines)) {
    state_->depth = queue_depth;
}

std::expected<std::shared_ptr<NerPool>, pc::DetectError> NerPool::make(const std::filesystem::path& dir,
                                                                         std::size_t workers,
                                                                         std::size_t queue_depth) {
    if (workers == 0 || queue_depth == 0) {
        return std::unexpected(pc::DetectError::Unavailable);
    }
    std::vector<NerEngine> engines;
    engines.reserve(workers);
    {
        // 모델 바이트(약 54 MB)는 세션이 복사해 가므로 엔진을 다 만들면 이 블록을 나가며 바로 버린다.
        const auto files = read_verified_model_files(dir);
        auto env = OrtEnv::create();
        if (!files || !env) {
            return std::unexpected(pc::DetectError::Unavailable);
        }
        for (std::size_t i = 0; i < workers; ++i) {
            auto engine = NerEngine::make(*files, *env);
            if (!engine) {
                return std::unexpected(engine.error());
            }
            engines.push_back(std::move(*engine));
        }
    }
    std::shared_ptr<NerPool> pool(new NerPool(std::move(engines), queue_depth));
    try {
        pool->threads_.reserve(workers);
        for (auto& engine : pool->engines_) {
            pool->threads_.emplace_back([p = pool.get(), &engine] { p->work(engine); });
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
        job.result.set_value(std::unexpected(pc::DetectError::Unavailable));
    }
}

void NerPool::work(NerEngine& engine) {
    for (;;) {
        std::optional<Job> job;
        {
            std::unique_lock lock(state_->mutex);
            state_->ready.wait(lock, [&] { return state_->stopping || !state_->jobs.empty(); });
            if (state_->stopping) {
                return;  // 남은 일은 소멸자가 거절한다
            }
            job.emplace(std::move(state_->jobs.front()));
            state_->jobs.pop_front();
        }
        auto found = engine.detect_all(job->text, job->segment, *job->view);
        if (found) {
            job->result.set_value(std::move(*found));
        } else {
            job->result.set_value(std::unexpected(to_detect_error(found.error())));
        }
    }
}

Result NerPool::scan(std::string_view text, pc::SegmentIndex segment, const detect::DetectionView& view) const {
    Job job{text, segment, &view, {}};
    auto result = job.result.get_future();
    {
        std::lock_guard lock(state_->mutex);
        if (state_->stopping) {
            return std::unexpected(pc::DetectError::Unavailable);
        }
        if (state_->jobs.size() >= state_->depth) {
            return std::unexpected(pc::DetectError::Overloaded);  // 기다리지 않는다
        }
        state_->jobs.push_back(std::move(job));
    }
    state_->ready.notify_one();
    return result.get();
}

}  // namespace prompt_airlock::ner
