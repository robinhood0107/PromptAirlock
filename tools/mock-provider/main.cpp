// mock provider 실행 파일(시연용).
// 사용: mock-provider <주소> <포트> <인증서 체인 PEM> <개인키 PEM> <자격 증명 파일> <기록 파일>
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

#include <cstdio>
#include <exception>
#include <fstream>
#include <iterator>
#include <string>

#include "mock_provider.hpp"
#include "prompt_airlock/provider/https_client.hpp"
#include "prompt_airlock/tls/context.hpp"

namespace {

std::string read_file(const char* path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

}  // namespace

int main(int argc, char** argv) try {
    if (argc != 7) {
        std::fputs("usage: mock-provider <address> <port> <cert-chain.pem> <key.pem> <credential-file> <record.jsonl>\n",
                   stderr);
        return 2;
    }
    namespace asio = boost::asio;
    auto tls = prompt_airlock::tls::make_server_context(read_file(argv[3]), read_file(argv[4]));
    const auto credential = prompt_airlock::provider::load_credential(argv[5]);
    if (!tls || !credential) {
        std::fputs("mock-provider: certificate, key or credential file is not usable\n", stderr);
        return 1;
    }
    asio::io_context io;
    const asio::ip::tcp::endpoint endpoint(asio::ip::make_address(argv[1]),
                                           static_cast<unsigned short>(std::stoul(argv[2])));
    pa_mock::MockProvider mock(io, *tls, endpoint, {std::string(credential->view()), argv[6]});
    mock.start();
    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&](auto, auto) { io.stop(); });
    std::printf("mock-provider listening on %s:%u\n", argv[1], static_cast<unsigned>(mock.local_endpoint().port()));
    std::fflush(stdout);
    io.run();
    return 0;
} catch (const std::exception& e) {
    std::fprintf(stderr, "mock-provider: %s\n", e.what());
    return 1;
}
