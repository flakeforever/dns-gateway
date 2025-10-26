//
// File: dns_monitor.hpp
// Description: HTTP monitoring interface for DNS upstream pool
//

#pragma once

#include "dns_upstream_pool.hpp"
#include <asio.hpp>
#include <memory>
#include <string>

namespace dns {

class dns_monitor {
public:
  dns_monitor(asio::any_io_executor executor, 
              dns_upstream_pool &pool,
              uint16_t port = 8080);
  ~dns_monitor();

  asio::awaitable<void> start();
  void stop();

private:
  asio::awaitable<void> handle_client(asio::ip::tcp::socket socket);
  std::string generate_stats_json();
  std::string generate_http_response(const std::string &body);
  
  asio::any_io_executor executor_;
  dns_upstream_pool &pool_;
  uint16_t port_;
  bool running_;
  std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
};

} // namespace dns

