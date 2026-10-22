// 시험 전용: Windows 에서 포트 0 listen 이 드물게 WSAEFAULT(10014)로 실패하는 현상(#118)을 피해 몇 번 다시 시도한다.
// 순수 asio 실험에서도 2000번 중 20번이 연달아 몰려 실패했다(환경 쪽 일시 현상). 잠깐 쉬었다가 다시 시도한다.
// 운영 코드는 다시 시도하지 않는다(실패하면 기동하지 않는다).
#pragma once

#include <chrono>
#include <system_error>
#include <thread>

namespace pa_test {

template <class F>
void retry_listen(F&& make) {
    for (int attempt = 1;; ++attempt) {
        try {
            make();
            return;
        } catch (const std::system_error&) {
            if (attempt == 20) {
                throw;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));  // 재시도 간격(동기화 용도 아님)
        }
    }
}

}  // namespace pa_test
