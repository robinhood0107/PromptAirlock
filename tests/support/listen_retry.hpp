// 시험 전용: Windows 에서 포트 0 listen·bind 가 WSAEFAULT(10014)로 연달아 실패하는 현상(#118)을 피해 다시 시도한다.
// 임시 포트는 거의 순서대로 배정되는데, 관리자 예약 범위(이 PC 는 50000~50059, 60개)를 지나는 동안 연속으로 실패하는 것으로 본다.
// 다음 시도는 다음 포트를 받으므로 기다리지 않고 예약 범위보다 많이 다시 시도한다. 운영 코드는 다시 시도하지 않는다.
#pragma once

#include <exception>

namespace pa_test {

template <class F>
void retry_listen(F&& make) {
    for (int attempt = 1;; ++attempt) {
        try {
            make();
            return;
        } catch (const std::exception&) {  // asio 는 boost::system::system_error(std::runtime_error 계열)를 던진다
            if (attempt == 100) {
                throw;
            }
        }
    }
}

}  // namespace pa_test
