// bounded producer-consumer queue spike. 가득 차면 기다리지 않고 overload 오류를 돌려줄 수 있다.
#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <expected>
#include <mutex>
#include <optional>
#include <stop_token>
#include <utility>

namespace pa_spike {

enum class QueueError { Full, Closed, Cancelled };

template <class T>
class BoundedQueue {
public:
    explicit BoundedQueue(std::size_t capacity) : capacity_(capacity) {}
    BoundedQueue(const BoundedQueue&) = delete;
    BoundedQueue& operator=(const BoundedQueue&) = delete;

    // 요청 경로용: 가득 차면 즉시 Full 을 돌려준다(secure overload).
    std::expected<void, QueueError> try_push(T value) {
        {
            std::scoped_lock lock(mutex_);
            if (closed_) return std::unexpected(QueueError::Closed);
            if (items_.size() >= capacity_) return std::unexpected(QueueError::Full);
            items_.push_back(std::move(value));
        }
        not_empty_.notify_one();
        return {};
    }

    // 내부 작업용: 공간이 생길 때까지 기다리되 stop 요청이나 close 로 깨어난다.
    std::expected<void, QueueError> push(T value, std::stop_token stop) {
        {
            std::unique_lock lock(mutex_);
            const bool ready = not_full_.wait(lock, stop, [&] { return closed_ || items_.size() < capacity_; });
            if (!ready) return std::unexpected(QueueError::Cancelled);
            if (closed_) return std::unexpected(QueueError::Closed);
            items_.push_back(std::move(value));
        }
        not_empty_.notify_one();
        return {};
    }

    // 항목이 없고 close 되었으면 nullopt. stop 요청이면 Cancelled.
    std::expected<std::optional<T>, QueueError> pop(std::stop_token stop) {
        std::optional<T> out;
        {
            std::unique_lock lock(mutex_);
            const bool ready = not_empty_.wait(lock, stop, [&] { return closed_ || !items_.empty(); });
            if (!ready) return std::unexpected(QueueError::Cancelled);
            if (items_.empty()) return std::optional<T>{};
            out.emplace(std::move(items_.front()));
            items_.pop_front();
        }
        not_full_.notify_one();
        return out;
    }

    void close() {
        {
            std::scoped_lock lock(mutex_);
            closed_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    [[nodiscard]] std::size_t size() const {
        std::scoped_lock lock(mutex_);
        return items_.size();
    }

private:
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable_any not_empty_;
    std::condition_variable_any not_full_;
    std::deque<T> items_;
    bool closed_ = false;
};

}  // namespace pa_spike
