// 시험·시연용 mock provider. 운영 빌드에 들어가지 않는다.
// 받은 요청 본문을 그대로 기록하고(시연: "밖으로 나간 내용"), 마지막 user 메시지를 인용한 답을 돌려준다.
#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace pa_mock {

struct MockOptions {
    std::string credential;              // 기대하는 Bearer 값
    std::filesystem::path record_file;   // 비어 있으면 파일에 쓰지 않는다
};

class MockProvider {
public:
    MockProvider(boost::asio::io_context& io, boost::asio::ssl::context& tls, const boost::asio::ip::tcp::endpoint& endpoint,
                 MockOptions options);
    void start();
    void stop();
    [[nodiscard]] boost::asio::ip::tcp::endpoint local_endpoint() const;
    // 지금까지 받은 요청 본문(인증에 성공한 것만).
    [[nodiscard]] std::vector<std::string> received() const;

    struct State;

private:
    std::shared_ptr<State> state_;
};

// 받은 요청 본문으로 Chat Completions 형식 답을 만든다. 시험에서 직접 확인할 수 있게 밖에 둔다.
[[nodiscard]] std::string make_answer(const std::string& request_body);

}  // namespace pa_mock
