#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <filesystem>
#include <string>
#include <vector>

#include "prompt_airlock/gateway/config.hpp"

namespace prompt_airlock::provider {

class CliClient {
public:
    CliClient(gateway::CliConfig config, std::string model_alias, boost::asio::any_io_executor work);

    [[nodiscard]] boost::asio::awaitable<std::expected<gateway::ProviderReply, gateway::ProviderError>> send(
        std::string prompt, std::uint32_t output_token_limit) const;

private:
    gateway::CliConfig config_;
    std::string model_alias_;
    boost::asio::any_io_executor work_;
};

}  // namespace prompt_airlock::provider
