// Asio C++20 coroutine 의 명시적 취소와 timeout 동작, 취소 후 정리 경로를 확인한다.
#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <chrono>
#include <optional>
#include <variant>

namespace asio = boost::asio;
using namespace std::chrono_literals;
using namespace boost::asio::experimental::awaitable_operators;

namespace {

// request scope 정리를 흉내 낸다. 취소돼도 소멸자에서 반드시 실행된다.
struct ScopeGuard {
    bool* dropped;
    ~ScopeGuard() { *dropped = true; }
};

enum class Outcome { Completed, Cancelled, Other };

asio::awaitable<Outcome> slow_detector(bool* dropped) {
    ScopeGuard guard{dropped};
    asio::steady_timer timer(co_await asio::this_coro::executor, 10s);
    auto [ec] = co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
    if (ec == asio::error::operation_aborted) co_return Outcome::Cancelled;
    co_return ec ? Outcome::Other : Outcome::Completed;
}

asio::awaitable<void> deadline(std::chrono::milliseconds d) {
    asio::steady_timer timer(co_await asio::this_coro::executor, d);
    co_await timer.async_wait(asio::use_awaitable);
}

}  // namespace

TEST(CoroutineCancel, CancellationSignalAbortsWaitAndRunsCleanup) {
    asio::io_context io;
    asio::cancellation_signal signal;
    bool dropped = false;
    std::optional<Outcome> outcome;

    asio::co_spawn(io, slow_detector(&dropped),
                   asio::bind_cancellation_slot(signal.slot(), [&](std::exception_ptr, Outcome o) { outcome = o; }));
    asio::steady_timer trigger(io, 10ms);
    trigger.async_wait([&](auto) { signal.emit(asio::cancellation_type::terminal); });

    const auto start = std::chrono::steady_clock::now();
    io.run();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    ASSERT_TRUE(outcome.has_value());
    EXPECT_EQ(*outcome, Outcome::Cancelled);
    EXPECT_TRUE(dropped);
    EXPECT_LT(elapsed, 2s);
}

TEST(CoroutineCancel, TimeoutViaParallelGroupCancelsLoser) {
    asio::io_context io;
    bool dropped = false;
    std::optional<std::size_t> winner;

    asio::co_spawn(
        io,
        [&]() -> asio::awaitable<void> {
            auto result = co_await (slow_detector(&dropped) || deadline(20ms));
            winner = result.index();
        },
        asio::detached);
    io.run();

    ASSERT_TRUE(winner.has_value());
    EXPECT_EQ(*winner, 1u);  // deadline 이 먼저 끝났다
    EXPECT_TRUE(dropped);    // 진 쪽 coroutine 도 정리 경로를 거쳤다
}
