pa_add_gtest(net_beast_https_test beast_https_test.cpp)
target_link_libraries(net_beast_https_test PRIVATE Boost::asio Boost::beast OpenSSL::SSL OpenSSL::Crypto)

if(PA_WITH_DROGON)
  find_package(Drogon CONFIG REQUIRED)
  pa_add_gtest(net_drogon_https_test drogon_https_test.cpp)
  target_link_libraries(net_drogon_https_test PRIVATE Drogon::Drogon Boost::asio OpenSSL::SSL OpenSSL::Crypto)
endif()
