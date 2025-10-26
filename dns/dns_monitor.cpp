//
// File: dns_monitor.cpp
// Description: HTTP monitoring interface implementation
//

#include "dns_monitor.hpp"
#include "../common/log.hpp"
#include <sstream>
#include <iomanip>

namespace dns {

dns_monitor::dns_monitor(asio::any_io_executor executor, 
                         dns_upstream_pool &pool,
                         uint16_t port)
    : executor_(executor), pool_(pool), port_(port), running_(false) {}

dns_monitor::~dns_monitor() {
  stop();
}

asio::awaitable<void> dns_monitor::start() {
  // Check if monitor is disabled (port 0)
  if (port_ == 0) {
    common::log.debug("dns monitor HTTP server disabled (port=0)");
    co_return;
  }
  
  try {
    acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(
        executor_, 
        asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port_));
    
    running_ = true;
    common::log.debug("dns monitor HTTP server started on port %d", port_);
    
    while (running_) {
      auto socket = co_await acceptor_->async_accept(asio::use_awaitable);
      
      // Spawn a new coroutine to handle this client
      asio::co_spawn(
          executor_,
          handle_client(std::move(socket)),
          [](std::exception_ptr e) {
            if (e) {
              try {
                std::rethrow_exception(e);
              } catch (const std::exception &ex) {
                common::log.error("monitor client handler error: %s", ex.what());
              }
            }
          });
    }
  } catch (const std::exception &e) {
    common::log.error("monitor server error: %s", e.what());
  }
  
  co_return;
}

void dns_monitor::stop() {
  running_ = false;
  if (acceptor_ && acceptor_->is_open()) {
    acceptor_->close();
  }
  common::log.info("dns monitor HTTP server stopped");
}

asio::awaitable<void> dns_monitor::handle_client(asio::ip::tcp::socket socket) {
  try {
    char buffer[1024];
    size_t n = co_await socket.async_read_some(
        asio::buffer(buffer), asio::use_awaitable);
    
    std::string request(buffer, n);
    
    // Simple HTTP request parsing (only handle GET /)
    if (request.find("GET /") == 0) {
      std::string json = generate_stats_json();
      std::string response = generate_http_response(json);
      
      co_await asio::async_write(
          socket, asio::buffer(response), asio::use_awaitable);
    }
    
    socket.close();
  } catch (const std::exception &e) {
    common::log.debug("monitor client error: %s", e.what());
  }
  
  co_return;
}

std::string dns_monitor::generate_stats_json() {
  std::ostringstream json;
  json << std::fixed << std::setprecision(2);
  
  json << "{\n";
  json << "  \"status\": \"ok\",\n";
  json << "  \"timestamp\": " << std::time(nullptr) << ",\n";
  json << "  \"groups\": [\n";
  
  auto group_names = pool_.get_all_group_names();
  bool first_group = true;
  
  for (const auto &group_name : group_names) {
    auto group = pool_.get_group(group_name);
    if (!group) continue;
    
    if (!first_group) json << ",\n";
    first_group = false;
    
    json << "    {\n";
    json << "      \"name\": \"" << group->name() << "\",\n";
    json << "      \"target_size\": " << group->target_size() << ",\n";
    json << "      \"total_instances\": " << group->get_total_instance_count() << ",\n";
    json << "      \"missing_count\": " << group->missing_count_.load(std::memory_order_relaxed) << ",\n";
    json << "      \"connections\": [\n";
    
    auto connections_list = group->get_all_connections();
    bool first_conn = true;
    
    for (const auto &conn : connections_list) {
      if (!first_conn) json << ",\n";
      first_conn = false;
      
      const auto &stats = conn->get_statistics();
      
      json << "        {\n";
      json << "          \"uri\": \"" << conn->data().uri << "\",\n";
      json << "          \"status\": \"";
      
      switch (conn->status()) {
        case connection_status::unknown:  json << "unknown"; break;
        case connection_status::active:   json << "active"; break;
        case connection_status::degraded: json << "degraded"; break;
        case connection_status::offline:  json << "offline"; break;
      }
      
      json << "\",\n";
      json << "          \"instances\": " << conn->get_instance_count() << ",\n";
      json << "          \"available\": " << conn->get_available_count() << ",\n";
      json << "          \"statistics\": {\n";
      json << "            \"total_requests\": " << stats.total_requests.load() << ",\n";
      json << "            \"success_requests\": " << stats.success_requests.load() << ",\n";
      json << "            \"failed_requests\": " << stats.failed_requests.load() << ",\n";
      json << "            \"success_rate\": " << std::fixed << std::setprecision(2) << stats.get_success_rate() << ",\n";
      json << "            \"avg_response_time_ms\": " << std::fixed << std::setprecision(2) << stats.get_avg_response_time_ms() << "\n";
      json << "          }\n";
      json << "        }";
    }
    
    json << "\n      ]\n";
    json << "    }";
  }
  
  json << "\n  ]\n";
  json << "}\n";
  
  return json.str();
}

std::string dns_monitor::generate_http_response(const std::string &body) {
  std::ostringstream response;
  
  response << "HTTP/1.1 200 OK\r\n";
  response << "Content-Type: application/json; charset=utf-8\r\n";
  response << "Content-Length: " << body.length() << "\r\n";
  response << "Connection: close\r\n";
  response << "Access-Control-Allow-Origin: *\r\n";
  response << "\r\n";
  response << body;
  
  return response.str();
}

} // namespace dns

