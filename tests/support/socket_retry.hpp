// 시험 전용: 이 Windows PC 에서 loopback 소켓의 bind·listen·connect 가 드물게 WSAEFAULT(10014)로 실패하는 현상(#118)을 다시 시도한다.
// Linux 에서는 나지 않는다. 다른 오류는 바로 올리고, 끝까지 실패하면 "환경 실패(#118)"와 시도 횟수·시간을 붙여 제품 결함과 구분한다.
// 운영 코드는 다시 시도하지 않는다.
#pragma once

#include <boost/asio/error.hpp>
#include <boost/system/system_error.hpp>

#include <chrono>
#include <stdexcept>
#include <string>

namespace pa_test {

// 실패는 한 번 나면 수십~수백 번 연달아 이어지므로 횟수 대신 시간으로 묶는다. 기다리지 않고 바로 다시 시도한다.
inline constexpr std::chrono::seconds socket_retry_window{3};

inline bool is_environment_fault(const boost::system::error_code& ec) { return ec == boost::asio::error::fault; }

class SocketRetry {
public:
    bool keep_going() {
        ++attempts_;
        return std::chrono::steady_clock::now() - start_ < socket_retry_window;
    }
    [[noreturn]] void fail(const boost::system::system_error& e) const {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_);
        throw std::runtime_error("환경 실패(#118), " + std::to_string(attempts_) + "회 " + std::to_string(elapsed.count()) +
                                 " ms 재시도 뒤 " + e.what());
    }

private:
    std::chrono::steady_clock::time_point start_ = std::chrono::steady_clock::now();
    int attempts_ = 0;
};

template <class F>
void retry_listen(F&& make) {
    SocketRetry retry;
    for (;;) {
        try {
            make();
            return;
        } catch (const boost::system::system_error& e) {
            if (!is_environment_fault(e.code())) {
                throw;
            }
            if (!retry.keep_going()) {
                retry.fail(e);
            }
        }
    }
}

// tcp_stream 을 닫고 다시 connect 한다. 거절을 기대하는 시험도 쓸 수 있게 환경 실패가 아닌 오류 코드는 그대로 돌려준다.
template <class Stream, class Endpoint>
boost::system::error_code retry_connect(Stream& stream, const Endpoint& endpoint) {
    SocketRetry retry;
    boost::system::error_code ec;
    do {
        stream.close();
        stream.connect(endpoint, ec);
    } while (is_environment_fault(ec) && retry.keep_going());
    if (is_environment_fault(ec)) {
        retry.fail(boost::system::system_error(ec, "connect"));
    }
    return ec;
}

}  // namespace pa_test
