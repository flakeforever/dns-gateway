//
// File: dns_upstream_pool.hpp
// Description: DNS upstream connection pool management
//
// Copyright (c) 2003-2025 The DNS-Gateway Authors.
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// This project uses the Asio library (https://think-async.com/Asio/) under the
// Boost Software License (https://www.boost.org/LICENSE_1_0.txt). This project
// uses OpenSSL (https://www.openssl.org) under the OpenSSL License
// (https://www.openssl.org/source/license.html).
//

#pragma once

#include "dns_upstream.hpp"
#include "dns_config.hpp"
#include "dns_buffer.hpp"
#include "property.hpp"
#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace dns {

enum class upstream_type { udp, tls, https };

enum class connection_status {
  unknown,    // Unknown state, not yet determined (initial state)
  active,     // Active and ready to handle requests
  degraded,   // Degraded state, experiencing issues, needs health check verification
  offline     // Offline and unavailable
};

// Statistics for connection performance monitoring
struct connection_statistics {
  std::atomic<uint64_t> total_requests{0};
  std::atomic<uint64_t> success_requests{0};
  std::atomic<uint64_t> failed_requests{0};
  std::atomic<int64_t> total_response_time_ms{0};  // Sum of all response times
  
  double get_avg_response_time_ms() const;
  double get_success_rate() const;
  void reset();
};

class dns_pool_connections;
class dns_pool_group;
class dns_upstream_pool;

class dns_pool_connections_property {
public:
  PROPERTY_READONLY(dns_upstream_data, data);
  PROPERTY_READWRITE(connection_status, status);
  PROPERTY_READWRITE(std::chrono::steady_clock::time_point, last_attempt_time);
  PROPERTY_READWRITE(std::chrono::steady_clock::time_point, status_change_time);
  PROPERTY_READWRITE(size_t, attempt_count);
};

class dns_pool_connections : public dns_pool_connections_property {
  friend class dns_pool_group;
  
public:
  dns_pool_connections(const dns_upstream_data &data,
                       asio::any_io_executor executor);
  ~dns_pool_connections();

  std::vector<std::shared_ptr<dns_upstream>> get_all_instances() const;
  size_t get_available_count() const;
  size_t get_instance_count() const;
  asio::awaitable<void> clear();
  
  std::shared_ptr<dns_upstream> create_single_instance();
  
  // Monitoring and statistics
  const dns_upstream_data &data() const { return data_; }
  connection_statistics &get_statistics() { return statistics_; }
  const connection_statistics &get_statistics() const { return statistics_; }

private:
  void create_instances();

  asio::any_io_executor executor_;
  std::vector<std::shared_ptr<dns_upstream>> instances_;
  mutable std::mutex mutex_;
  
  // Track last check time for each upstream instance
  std::unordered_map<std::shared_ptr<dns_upstream>, std::chrono::steady_clock::time_point> last_check_times_;
  
  // Performance statistics
  connection_statistics statistics_;
};

class dns_pool_group_property {
public:
  PROPERTY_READONLY(std::string, name);
  PROPERTY_READONLY(size_t, target_size);
  
  // Statistics for this group
  std::atomic<uint64_t> missing_count_{0};  // Count when failed to get an upstream
};

class dns_pool_group : public dns_pool_group_property {
public:
  dns_pool_group(const std::string &group_name, size_t target_size,
                 asio::any_io_executor executor);
  ~dns_pool_group();

  asio::awaitable<void> init();
  asio::awaitable<void> balance_load();
  asio::awaitable<void> handle_check();

  std::shared_ptr<dns_pool_connections>
  add_upstream(const dns_upstream_data &data);

  void add_connections(std::shared_ptr<dns_pool_connections> connections);

  asio::awaitable<std::shared_ptr<dns_upstream>> get_next_upstream();
  std::vector<std::shared_ptr<dns_pool_connections>>
  get_all_connections() const;
  size_t get_connections_count() const;
  size_t get_total_instance_count() const;
  asio::awaitable<void> clear();

private:
  // Balance load sub-methods for better readability
  asio::awaitable<void> scale_down(
    std::vector<std::shared_ptr<dns_pool_connections>> &active_connections,
    size_t current_instance_count);
  
  asio::awaitable<void> rebalance_distribution(
    std::vector<std::shared_ptr<dns_pool_connections>> &active_connections);
  
  asio::awaitable<void> scale_up(
    std::vector<std::shared_ptr<dns_pool_connections>> &active_connections,
    size_t current_instance_count);
  
  // Health check sub-methods for better readability
  asio::awaitable<void> check_active_connections(
    std::shared_ptr<dns_pool_connections> connections,
    std::chrono::steady_clock::time_point now);
  
  asio::awaitable<void> recover_degraded_connections(
    std::shared_ptr<dns_pool_connections> connections,
    std::chrono::steady_clock::time_point now);
  
  asio::awaitable<void> recover_offline_connections(
    std::shared_ptr<dns_pool_connections> connections,
    std::chrono::steady_clock::time_point now);
  
  // Reset cumulative counters for fair competition when instance count changes
  void reset_all_cumulative_counters();

  asio::any_io_executor executor_;
  std::vector<std::shared_ptr<dns_pool_connections>> connections_list_;
  size_t current_index_;
  size_t last_total_instance_count_{0};  // Track instance count for change detection
  mutable std::mutex mutex_;
  char check_buffer_[dns::buffer_size];
};

class dns_upstream_pool {
public:
  explicit dns_upstream_pool(asio::any_io_executor executor);
  ~dns_upstream_pool();

  asio::awaitable<void> init();

  std::shared_ptr<dns_pool_group> create_group(const std::string &group_name);
  std::shared_ptr<dns_pool_group> create_group(const std::string &group_name,
                                                size_t target_size);
  std::shared_ptr<dns_pool_group> get_group(const std::string &group_name);
  std::shared_ptr<dns_pool_group> get_group(const std::string &group_name) const;
  bool has_group(const std::string &group_name) const;
  asio::awaitable<bool> remove_group(const std::string &group_name);
  std::vector<std::string> get_all_group_names() const;
  size_t get_group_count() const;
  size_t get_total_upstream_count() const;
  asio::awaitable<void> clear_all();
  void set_default_group(const std::string &group_name);
  std::shared_ptr<dns_pool_group> get_default_group();
  
  // Get next upstream from a group
  asio::awaitable<std::shared_ptr<dns_upstream>>
  get_next_upstream(const std::string &group_name);

private:
  asio::any_io_executor executor_;
  std::unordered_map<std::string, std::shared_ptr<dns_pool_group>> groups_;
  std::shared_ptr<dns_pool_group> default_group_;
  mutable std::mutex mutex_;
};

} // namespace dns

