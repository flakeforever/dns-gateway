//
// File: dns_upstream_pool.cpp
// Description: DNS upstream connection pool implementation
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

#include "dns_upstream_pool.hpp"
#include "dns_utils.hpp"
#include "../common/log.hpp"
#include "dns_package.hpp"
#include "operation.hpp"
#include <algorithm>
#include <stdexcept>

using asio::awaitable;

namespace dns {

// ========== dns_pool_connections implementation ==========

dns_pool_connections::dns_pool_connections(
    const dns_upstream_data &data, asio::any_io_executor executor)
    : executor_(executor) {
  
  data_ = data;
  status_ = connection_status::unknown;
  last_attempt_time_ = std::chrono::steady_clock::now();
  status_change_time_ = std::chrono::steady_clock::now();
  attempt_count_ = 0;

  common::log.debug("dns_upstream_connections created: %s (status: unknown)", 
                    data_.uri.c_str());

  // Don't create instances here, will be created during init
}

dns_pool_connections::~dns_pool_connections() {
  common::log.debug("dns_upstream_connections destroyed: %s", data_.uri.c_str());
}

asio::awaitable<std::shared_ptr<dns_upstream>>
dns_pool_connections::create_single_instance() {
  std::shared_ptr<dns_upstream> instance;
  
  // Parse upstream URI using utility function
  upstream_uri parsed = parse_upstream_uri(data_.uri);
  
  if (!parsed.is_valid()) {
    common::log.error("failed to parse upstream URI: %s", data_.uri.c_str());
    co_return nullptr;
  }
  
  // Parse proxy URI if present
  proxy_uri proxy;
  if (!data_.proxy.empty()) {
    proxy = parse_proxy_uri(data_.proxy);
    if (!proxy.is_valid()) {
      common::log.warning("failed to parse proxy URI: %s, continuing without proxy", 
                          data_.proxy.c_str());
    }
  }
  
  // Create upstream instance based on scheme
  switch (parsed.scheme) {
    case uri_scheme::udp: {
      auto udp_upstream = std::make_shared<dns_udp_upstream>(
          executor_, parsed.host, parsed.port);
      
      // Apply proxy settings
      if (proxy.is_valid()) {
        udp_upstream->set_proxy(socks::proxy_type::socks5, 
                                proxy.host, proxy.port);
      }
      
      // Apply check settings
      udp_upstream->check_enabled(data_.check_enabled);
      udp_upstream->check_interval(data_.check_interval);
      udp_upstream->set_check_domains(data_.check_domains);
      
      instance = udp_upstream;
      common::log.info("created UDP upstream instance: %s", data_.uri.c_str());
      break;
    }
    
    case uri_scheme::tls:
    case uri_scheme::dot: {
      auto tls_upstream = std::make_shared<dns_tls_upstream>(
          executor_, parsed.host, parsed.port);
      
      // Apply proxy settings
      if (proxy.is_valid()) {
        tls_upstream->set_proxy(socks::proxy_type::socks5, 
                                proxy.host, proxy.port);
      }
      
      // Apply TLS settings
      tls_upstream->keep_alive(data_.keep_alive);
      tls_upstream->security_verify(data_.security_verify);
      tls_upstream->ca_certificate(data_.ca_certificate);
      tls_upstream->certificate(data_.certificate);
      tls_upstream->private_key(data_.private_key);
      
      // Apply check settings
      tls_upstream->check_enabled(data_.check_enabled);
      tls_upstream->check_interval(data_.check_interval);
      tls_upstream->set_check_domains(data_.check_domains);
      
      instance = tls_upstream;
      common::log.info("created TLS upstream instance: %s", data_.uri.c_str());
      break;
    }
    
    case uri_scheme::https:
    case uri_scheme::doh: {
      // Determine HTTP version: default 1.1, use 2 if specified
      if (data_.version == "2") {
        // Create HTTP/2 upstream (multiplexing)
        auto http2_upstream = std::make_shared<dns_http2_upstream>(
            executor_, parsed.host, parsed.port, parsed.path);
        
        // Apply proxy settings
        if (proxy.is_valid()) {
          http2_upstream->set_proxy(socks::proxy_type::socks5, 
                                    proxy.host, proxy.port);
        }
        
        // Apply HTTP/2 settings
        http2_upstream->path(parsed.path);
        http2_upstream->security_verify(data_.security_verify);
        http2_upstream->ca_certificate(data_.ca_certificate);
        http2_upstream->certificate(data_.certificate);
        http2_upstream->private_key(data_.private_key);
        
        // Apply check settings
        http2_upstream->check_enabled(data_.check_enabled);
        http2_upstream->check_interval(data_.check_interval);
        http2_upstream->set_check_domains(data_.check_domains);
        
        instance = http2_upstream;
        common::log.info("created HTTP/2 (DoH) upstream instance: %s (version=%s)", 
                        data_.uri.c_str(), data_.version.c_str());
      } else {
        // Create HTTP/1.1 upstream (default)
        auto https_upstream = std::make_shared<dns_https_upstream>(
            executor_, parsed.host, parsed.port, parsed.path);
        
        // Apply proxy settings
        if (proxy.is_valid()) {
          https_upstream->set_proxy(socks::proxy_type::socks5, 
                                    proxy.host, proxy.port);
        }
        
        // Apply HTTPS settings (HTTPS inherits from TLS)
        https_upstream->keep_alive(data_.keep_alive);
        https_upstream->security_verify(data_.security_verify);
        https_upstream->ca_certificate(data_.ca_certificate);
        https_upstream->certificate(data_.certificate);
        https_upstream->private_key(data_.private_key);
        
        // Apply check settings
        https_upstream->check_enabled(data_.check_enabled);
        https_upstream->check_interval(data_.check_interval);
        https_upstream->set_check_domains(data_.check_domains);
        
        instance = https_upstream;
        common::log.info("created HTTP/1.1 (DoH) upstream instance: %s (version=%s)", 
                        data_.uri.c_str(), data_.version.c_str());
      }
      break;
    }
    
    default:
      common::log.error("unsupported URI scheme in: %s", data_.uri.c_str());
      co_return nullptr;
  }

  // Try to open the instance with timeout before returning
  bool opened = co_await open_instance(instance);
  if (!opened) {
    co_return nullptr;
  }

  co_return instance;
}

asio::awaitable<bool>
dns_pool_connections::open_instance(std::shared_ptr<dns_upstream> instance) {
  async_timeout_execute timeout_execute(executor_);
  
  try {
    co_await timeout_execute.execute_until(
        std::chrono::milliseconds(dns::connect_timeout),
        [&instance, &timeout_execute](asio::steady_timer &timer) -> asio::awaitable<void> {
          try {
            bool result = co_await instance->open();
            if (!result) {
              throw std::runtime_error("open() returned false");
            }
          } catch (const std::exception &e) {
            common::log.debug("exception when opening upstream instance: %s", e.what());
            throw;
          }
          
          // Cancel timer if operation succeeded
          if (!timeout_execute.timeout()) {
            timer.cancel();
          }
        });
    
    // Check if timed out
    if (timeout_execute.timeout()) {
      common::log.warning("timeout when opening upstream instance: %s", data_.uri.c_str());
      instance->close();
      co_return false;
    }
  } catch (const std::exception &e) {
    common::log.debug("exception when opening upstream instance %s: %s",
                     data_.uri.c_str(), e.what());
    if (instance) {
      instance->close();
    }
    co_return false;
  }

  co_return true;
}

std::vector<std::shared_ptr<dns_upstream>>
dns_pool_connections::get_all_instances() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return instances_;
}

size_t dns_pool_connections::get_available_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  size_t count = 0;
  for (const auto &instance : instances_) {
    // Multiplexing instances are always available for concurrent requests
    // Non-multiplexing instances (DoT/DoH) are only available if not locked
    if (instance->supports_multiplexing() || instance->mutex_.try_lock()) {
      if (!instance->supports_multiplexing()) {
        instance->mutex_.unlock();  // Release immediately, we just checked
      }
      count++;
    }
  }
  return count;
}

size_t dns_pool_connections::get_instance_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return instances_.size();
}

asio::awaitable<void> dns_pool_connections::clear() {
  std::vector<std::shared_ptr<dns_upstream>> instances_to_close;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    instances_to_close = std::move(instances_);
    instances_.clear();
  }

  // Close all instances (execute outside lock)
  for (auto &instance : instances_to_close) {
    try {
      co_await instance->close();
    } catch (const std::exception &e) {
      common::log.error("error closing upstream instance %s: %s",
                        data_.uri.c_str(), e.what());
    }
  }

  common::log.debug("cleared all instances in connections %s", 
                    data_.uri.c_str());
}

// ========== dns_pool_group implementation ==========

dns_pool_group::dns_pool_group(const std::string &group_name,
                                       size_t target_size,
                                       asio::any_io_executor executor)
    : executor_(executor), current_index_(0) {
  name_ = group_name;
  target_size_ = target_size;
  common::log.debug("dns_upstream_group created: %s, target_size: %zu",
                    name().c_str(), target_size_);
}

dns_pool_group::~dns_pool_group() {
  common::log.debug("dns_upstream_group destroyed: %s", name().c_str());
}

asio::awaitable<void> dns_pool_group::init() {
  std::vector<std::shared_ptr<dns_pool_connections>> connections_to_init;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_to_init = connections_list_;
  }

  common::log.debug("initializing group '%s' with %zu connections",
                    name().c_str(), connections_to_init.size());

  // Initialize each connections
  for (auto &connections : connections_to_init) {
    // Create single instance for this connections (includes opening with timeout)
    auto instance = co_await connections->create_single_instance();
    
    if (!instance) {
      // Failed to create or open instance
      connections->status_ = connection_status::offline;
      common::log.error("failed to create instance for connections %s, status: offline",
                        connections->data_.uri.c_str());
      continue;
    }

    // Successfully opened (already validated in upstream->open for TLS/HTTPS)
    std::lock_guard<std::mutex> lock(connections->mutex_);
    connections->instances_.push_back(instance);
    connections->status_ = connection_status::active;
    common::log.debug("connections %s initialized successfully, status: active",
                      connections->data_.uri.c_str());
  }

  // Balance load after initialization
  co_await balance_load();

  // Initialize last_total_instance_count after init
  {
    std::lock_guard<std::mutex> lock(mutex_);
    last_total_instance_count_ = 0;
    for (const auto &connections : connections_list_) {
      if (connections->status_ == connection_status::active) {
        last_total_instance_count_ += connections->get_instance_count();
      }
    }
  }

  common::log.debug("group '%s' initialization completed", name().c_str());
}

asio::awaitable<void> dns_pool_group::balance_load() {
  if (target_size_ == 0) {
    common::log.debug("group '%s' has no target_size, skipping load balancing",
                      name().c_str());
    co_return;
  }

  std::vector<std::shared_ptr<dns_pool_connections>> active_connections;
  size_t current_instance_count = 0;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Collect active connections and count current instances
    for (auto &connections : connections_list_) {
      if (connections->status_ == connection_status::active) {
        active_connections.push_back(connections);
        current_instance_count += connections->get_instance_count();
      }
    }
  }

  if (active_connections.empty()) {
    common::log.warning("group '%s' has no active connections for load balancing",
                        name().c_str());
    co_return;
  }

  // common::log.debug("group '%s' load balancing: target=%zu, current=%zu, active_connections=%zu",
  //                   name().c_str(), target_size_, current_instance_count, 
  //                   active_connections.size());

  // Dispatch to appropriate sub-method based on current state
  if (current_instance_count > target_size_) {
    // Too many instances - scale down
    co_await scale_down(active_connections, current_instance_count);
  } else if (current_instance_count == target_size_) {
    // Target reached - check if rebalancing is needed
    co_await rebalance_distribution(active_connections);
  } else {
    // Not enough instances - scale up
    co_await scale_up(active_connections, current_instance_count);
  }
  
  // common::log.debug("group '%s' load balancing completed", name().c_str());
}

// Scale down: remove excess instances to reach target
asio::awaitable<void> dns_pool_group::scale_down(
    std::vector<std::shared_ptr<dns_pool_connections>> &active_connections,
    size_t current_instance_count) {
  
  size_t instances_to_remove = current_instance_count - target_size_;
  common::log.debug("group '%s' has too many instances, need to remove %zu",
                    name().c_str(), instances_to_remove);
  
  // Sort connections by instance count (descending)
  std::sort(active_connections.begin(), active_connections.end(),
            [](const auto &a, const auto &b) {
              return a->get_instance_count() > b->get_instance_count();
            });
  
  // Remove instances from connections with the most instances first
  for (auto &connections : active_connections) {
    if (instances_to_remove == 0) break;
    
    size_t current_count = connections->get_instance_count();
    if (current_count <= 1) continue;  // Keep at least 1 instance per connection
    
    // Calculate how many to remove from this connections (at most half, rounded down)
    size_t can_remove = std::min(instances_to_remove, (current_count - 1) / 2 + (current_count - 1) % 2);
    
    if (can_remove > 0) {
      std::vector<std::shared_ptr<dns_upstream>> instances_to_close;
      {
        std::lock_guard<std::mutex> lock(connections->mutex_);
        // Remove from the end (LIFO)
        for (size_t i = 0; i < can_remove && !connections->instances_.empty(); ++i) {
          auto instance = connections->instances_.back();
          connections->instances_.pop_back();
          instances_to_close.push_back(instance);
        }
      }
      
      // Close instances outside the lock
      for (auto &instance : instances_to_close) {
        co_await instance->close();
      }
      
      common::log.debug("removed %zu instances from connections %s (had %zu)",
                        instances_to_close.size(), connections->data_.uri.c_str(), current_count);
      
      instances_to_remove -= instances_to_close.size();
    }
  }
  
  common::log.debug("group '%s' scale-down completed", name().c_str());
}

// Rebalance distribution: redistribute instances evenly across connections
asio::awaitable<void> dns_pool_group::rebalance_distribution(
    std::vector<std::shared_ptr<dns_pool_connections>> &active_connections) {
  
  // Check if distribution is balanced
  size_t ideal_per_connection = target_size_ / active_connections.size();
  size_t remainder = target_size_ % active_connections.size();
  
  // Determine tolerance based on scale: stricter for smaller pools
  // For small pools (< 20 instances), require exact distribution
  // For larger pools, allow ±1 variance
  size_t tolerance = (target_size_ >= 20) ? 1 : 0;
  
  bool needs_rebalance = false;
  for (size_t i = 0; i < active_connections.size(); ++i) {
    size_t expected = ideal_per_connection + (i < remainder ? 1 : 0);
    size_t actual = active_connections[i]->get_instance_count();
    
    // Check if actual deviates from expected by more than tolerance
    if (actual > expected + tolerance || (actual + tolerance < expected && expected > 0)) {
      needs_rebalance = true;
      break;
    }
  }
  
  if (!needs_rebalance) {
    // common::log.debug("group '%s' already has target instances (%zu) with balanced distribution",
    //                   name().c_str(), target_size_);
    co_return;
  }
  
  common::log.debug("group '%s' has target instances (%zu) but distribution is unbalanced, rebalancing",
                    name().c_str(), target_size_);
  
  // Rebalance strategy: First ADD to under-provisioned, then REMOVE from over-provisioned
  // This ensures capacity is always >= target during rebalancing
  
  // Step 1: Add instances to under-provisioned connections first
  for (size_t i = 0; i < active_connections.size(); ++i) {
    auto &connections = active_connections[i];
    size_t current_count = connections->get_instance_count();
    size_t expected = ideal_per_connection + (i < remainder ? 1 : 0);
    
    // Use the same tolerance for consistency
    if (current_count + tolerance < expected && expected > 0) {
      // This connections needs more
      size_t to_add = expected - current_count;
      size_t added = 0;
      
      for (size_t j = 0; j < to_add; ++j) {
        auto instance = co_await connections->create_single_instance();
        if (!instance) continue;
        
        std::lock_guard<std::mutex> lock(connections->mutex_);
        connections->instances_.push_back(instance);
        added++;
      }
      
      if (added > 0) {
        common::log.debug("rebalance: added %zu instances to connections %s (had %zu, expected %zu)",
                          added, connections->data_.uri.c_str(), current_count, expected);
        // Reset cumulative counters for fair competition after adding instances
        reset_all_cumulative_counters();
      }
    }
  }
  
  // Step 2: Now remove excess instances from over-provisioned connections
  // Sort by instance count descending to prioritize removing from the most over-provisioned
  std::sort(active_connections.begin(), active_connections.end(),
            [](const auto &a, const auto &b) {
              return a->get_instance_count() > b->get_instance_count();
            });
  
  for (size_t i = 0; i < active_connections.size(); ++i) {
    auto &connections = active_connections[i];
    size_t current_count = connections->get_instance_count();
    size_t expected = ideal_per_connection + (i < remainder ? 1 : 0);
    
    // Use the same tolerance for consistency
    if (current_count > expected + tolerance) {
      // This connections has too many, remove excess
      size_t to_remove = current_count - expected;
      
      std::vector<std::shared_ptr<dns_upstream>> instances_to_close;
      {
        std::lock_guard<std::mutex> lock(connections->mutex_);
        // Remove from the end (LIFO - keep older, more stable connections)
        for (size_t j = 0; j < to_remove && !connections->instances_.empty(); ++j) {
          auto instance = connections->instances_.back();
          connections->instances_.pop_back();
          instances_to_close.push_back(instance);
        }
      }
      
      // Close instances outside the lock
      for (auto &instance : instances_to_close) {
        co_await instance->close();
      }
      
      common::log.debug("rebalance: removed %zu instances from connections %s (had %zu, expected %zu)",
                        instances_to_close.size(), connections->data_.uri.c_str(), 
                        current_count, expected);
    }
  }
  
  common::log.debug("group '%s' rebalancing completed", name().c_str());
}

// Scale up: create new instances to reach target
asio::awaitable<void> dns_pool_group::scale_up(
    std::vector<std::shared_ptr<dns_pool_connections>> &active_connections,
    size_t current_instance_count) {
  
  // Calculate how many more instances we need
  size_t instances_needed = target_size_ - current_instance_count;
  common::log.debug("group '%s' needs %zu more instances",
                    name().c_str(), instances_needed);

  // Distribute instances evenly across active connections (one-time check)
  size_t connections_count = active_connections.size();
  size_t instances_per_connection = instances_needed / connections_count;
  size_t remainder = instances_needed % connections_count;

  for (size_t i = 0; i < active_connections.size(); ++i) {
    auto &connections = active_connections[i];
    
    // Calculate how many instances to create for this connections
    size_t instances_to_create = instances_per_connection;
    if (i < remainder) {
      instances_to_create++; // Distribute remainder to first few connections
    }

    if (instances_to_create == 0) {
      continue;
    }

    common::log.debug("creating %zu additional instances for connections %s",
                      instances_to_create, connections->data_.uri.c_str());

    size_t created_count = 0;
    size_t failed_count = 0;

    // Create and open instances (one-time attempt per instance)
    for (size_t j = 0; j < instances_to_create; ++j) {
      auto instance = co_await connections->create_single_instance();
      
      if (!instance) {
        failed_count++;
        common::log.debug("failed to create additional instance %zu/%zu for connections %s, ignoring",
                          j + 1, instances_to_create, connections->data_.uri.c_str());
        continue; // Ignore this instance and move to next
      }

      // Successfully opened, add to instances
      {
        std::lock_guard<std::mutex> lock(connections->mutex_);
        connections->instances_.push_back(instance);
      }
      created_count++;
    }

    common::log.debug("connections %s: created %zu/%zu instances (%zu failed/ignored)",
                      connections->data_.uri.c_str(), created_count, 
                      instances_to_create, failed_count);
  }

  common::log.debug("group '%s' scale-up completed", name().c_str());
  
  // Reset cumulative counters for fair competition after scaling up
  reset_all_cumulative_counters();
}

// Reset cumulative counters for all instances in this group for fair competition
void dns_pool_group::reset_all_cumulative_counters() {
  std::lock_guard<std::mutex> lock(mutex_);
  
  // Count current total instances
  size_t current_total = 0;
  for (const auto &connections : connections_list_) {
    if (connections->status_ == connection_status::active) {
      current_total += connections->get_instance_count();
    }
  }
  
  // If instance count changed, reset all cumulative counters for fair competition
  if (current_total != last_total_instance_count_) {
    size_t reset_count = 0;
    for (const auto &connections : connections_list_) {
      if (connections->status_ == connection_status::active) {
        auto instances = connections->get_all_instances();
        for (auto &instance : instances) {
          instance->cumulative_requests_.store(0, std::memory_order_relaxed);
          reset_count++;
        }
      }
    }
    
    common::log.info("group '%s': instance count changed from %zu to %zu, reset %zu cumulative counters for fair competition",
                     name().c_str(), last_total_instance_count_, current_total, reset_count);
    
    last_total_instance_count_ = current_total;
  }
}

std::shared_ptr<dns_pool_connections>
dns_pool_group::add_upstream(const dns_upstream_data &data) {
  // Validate URI using utility function
  upstream_uri parsed = parse_upstream_uri(data.uri);
  if (!parsed.is_valid()) {
    common::log.error("invalid upstream URI: %s", data.uri.c_str());
    return nullptr;
  }
  
  // Create connections with data copy
  auto connections = std::make_shared<dns_pool_connections>(data, executor_);
  
  if (connections) {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_list_.push_back(connections);
    common::log.debug("added connections to group '%s': %s",
                      name().c_str(), data.uri.c_str());
  }
  
  return connections;
}

void dns_pool_group::add_connections(
    std::shared_ptr<dns_pool_connections> connections) {
  if (!connections) {
    common::log.error("attempt to add null connections to group '%s'",
                      name().c_str());
    return;
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_list_.push_back(connections);
  }

  common::log.debug("added connections to group '%s', total: %zu",
                    name().c_str(), connections_list_.size());
}

asio::awaitable<std::shared_ptr<dns_upstream>>
dns_pool_group::get_next_upstream() {
  // Build a flat list of all available upstream instances from all active connections
  struct InstanceInfo {
    std::shared_ptr<dns_upstream> instance;
    std::shared_ptr<dns_pool_connections> connections;
  };
  
  std::vector<InstanceInfo> all_instances;
  
  {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (connections_list_.empty()) {
      missing_count_.fetch_add(1, std::memory_order_relaxed);
      common::log.error("no connections available in group '%s'",
                        name().c_str());
      co_return nullptr;
    }
    
    // Collect all available instances from active connections
    for (const auto &connections : connections_list_) {
      if (connections->status_ == connection_status::active) {
        auto instances = connections->get_all_instances();
        for (const auto &instance : instances) {
          all_instances.push_back({instance, connections});
        }
      }
    }
    
    if (all_instances.empty()) {
      missing_count_.fetch_add(1, std::memory_order_relaxed);
      common::log.warning("no available instances in group '%s'",
                          name().c_str());
      co_return nullptr;
    }
  }

  // Least Requests load balancing: select instance with minimum cumulative requests
  std::shared_ptr<dns_upstream> best_instance = nullptr;
  std::shared_ptr<dns_pool_connections> best_connections = nullptr;
  uint64_t min_requests = UINT64_MAX;
  size_t best_index = 0;
  
  // Find the instance with the least cumulative requests
  for (size_t i = 0; i < all_instances.size(); i++) {
    auto &info = all_instances[i];
    
    // Multiplexing instances (UDP) can handle concurrent requests, no need to check
    // Non-multiplexing instances (DoT/DoH), check if locked (busy)
    if (!info.instance->supports_multiplexing() && !info.instance->mutex_.try_lock()) {
      continue;  // Skip busy instances (DoT/DoH only)
    }
    if (!info.instance->supports_multiplexing()) {
      info.instance->mutex_.unlock();  // Release immediately, we just checked
    }
    
    // Get cumulative request count (never reset)
    uint64_t cumulative = info.instance->cumulative_requests_.load(std::memory_order_relaxed);
    
    if (cumulative < min_requests) {
      min_requests = cumulative;
      best_instance = info.instance;
      best_connections = info.connections;
      best_index = i;
    }
  }
  
  // Return the instance with the least requests (if found)
  // Note: We don't lock here - the lock will be managed by async_mutex_lock in dns_upstream_request
  if (best_instance) {
    common::log.debug("selected upstream instance %zu/%zu (cumulative_requests=%lu) from group '%s', connections: %s",
                      best_index, all_instances.size(), min_requests, name().c_str(), 
                      best_connections->data_.uri.c_str());
    co_return best_instance;
  }

  // All instances are currently locked (busy), record and return null
  missing_count_.fetch_add(1, std::memory_order_relaxed);
  
  common::log.warning("all instances in group '%s' are busy (%zu total)",
                      name().c_str(), all_instances.size());
  co_return nullptr;
}

std::vector<std::shared_ptr<dns_pool_connections>>
dns_pool_group::get_all_connections() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return connections_list_;
}

size_t dns_pool_group::get_connections_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return connections_list_.size();
}

size_t dns_pool_group::get_total_instance_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  size_t total = 0;
  for (const auto &connections : connections_list_) {
    total += connections->get_instance_count();
  }
  return total;
}

asio::awaitable<void> dns_pool_group::clear() {
  std::vector<std::shared_ptr<dns_pool_connections>> connections_to_clear;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    connections_to_clear = std::move(connections_list_);
    connections_list_.clear();
  }

  // Clear all connections (execute outside lock)
  for (auto &connections : connections_to_clear) {
    co_await connections->clear();
  }

  common::log.debug("cleared all connections in group '%s'",
                    name().c_str());
}

// ========== dns_upstream_pool implementation ==========

dns_upstream_pool::dns_upstream_pool(asio::any_io_executor executor)
    : executor_(executor) {
  common::log.debug("dns_upstream_pool created");
}

dns_upstream_pool::~dns_upstream_pool() {
  common::log.debug("dns_upstream_pool destroyed");
}

asio::awaitable<void> dns_upstream_pool::init() {
  std::vector<std::shared_ptr<dns_pool_group>> groups_to_init;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &pair : groups_) {
      groups_to_init.push_back(pair.second);
    }
  }

  common::log.debug("initializing dns_upstream_pool with %zu groups",
                    groups_to_init.size());

  // Initialize all groups
  for (auto &group : groups_to_init) {
    co_await group->init();
  }

  common::log.debug("dns_upstream_pool initialization completed");

  // Start health check coroutine for each group
  for (auto &group : groups_to_init) {
    asio::co_spawn(
        executor_,
        [group]() -> asio::awaitable<void> {
          co_await group->handle_check();
        },
        asio::detached);
    common::log.debug("health check coroutine started for group '%s'", 
                      group->name().c_str());
  }
}

asio::awaitable<void> dns_pool_group::handle_check() {
  common::log.debug("group '%s' health check started", name().c_str());
  
  asio::steady_timer timer(executor_);
  auto last_balance_time = std::chrono::steady_clock::now();
  const auto balance_interval = std::chrono::seconds(5);
  
  while (true) {
    try {
      // Wait 1 second
      timer.expires_after(std::chrono::seconds(1));
      co_await timer.async_wait(asio::use_awaitable);
      
      auto now = std::chrono::steady_clock::now();
      std::vector<std::shared_ptr<dns_pool_connections>> connections_list;
      
      {
        std::lock_guard<std::mutex> lock(mutex_);
        connections_list = connections_list_;
      }
      
      // Process all connections in this group based on their status
      for (auto &connections : connections_list) {
        auto current_status = connections->status_;
        
        if (current_status == connection_status::active) {
          co_await check_active_connections(connections, now);
        } else if (current_status == connection_status::degraded) {
          co_await recover_degraded_connections(connections, now);
        } else if (current_status == connection_status::offline) {
          co_await recover_offline_connections(connections, now);
        }
      }
      
      // Run load balancing every 5 seconds
      auto time_since_balance = std::chrono::duration_cast<std::chrono::seconds>(
          now - last_balance_time).count();
      
      if (time_since_balance >= balance_interval.count()) {
        // common::log.debug("group '%s': running load balancing", name().c_str());
        co_await balance_load();
        last_balance_time = now;
      }
      
    } catch (const std::exception &e) {
      common::log.error("group '%s': exception in health check: %s", 
                        name().c_str(), e.what());
      // Continue running even if there's an error
    }
  }
  
  co_return;
}

// Check active connections: aggregate statistics, remove closed instances, perform health checks
asio::awaitable<void> dns_pool_group::check_active_connections(
    std::shared_ptr<dns_pool_connections> connections,
    std::chrono::steady_clock::time_point now) {
  
  std::vector<std::shared_ptr<dns_upstream>> instances_to_check;
  {
    std::lock_guard<std::mutex> lock(connections->mutex_);
    instances_to_check = connections->instances_;
  }
  
  // First, aggregate statistics from ALL instances (before checking health)
  uint64_t total_req = 0, total_succ = 0, total_fail = 0;
  int64_t total_resp_time = 0;
  
  for (auto &instance : instances_to_check) {
    // Read and reset statistics atomically
    uint64_t req = instance->request_count_.exchange(0, std::memory_order_relaxed);
    uint64_t succ = instance->success_count_.exchange(0, std::memory_order_relaxed);
    uint64_t fail = instance->failed_count_.exchange(0, std::memory_order_relaxed);
    int64_t resp_time = instance->total_response_time_ms_.exchange(0, std::memory_order_relaxed);
    
    total_req += req;
    total_succ += succ;
    total_fail += fail;
    total_resp_time += resp_time;
  }
  
  // Aggregate to connections statistics
  if (total_req > 0) {
    connections->statistics_.total_requests.fetch_add(total_req, std::memory_order_relaxed);
    connections->statistics_.success_requests.fetch_add(total_succ, std::memory_order_relaxed);
    connections->statistics_.failed_requests.fetch_add(total_fail, std::memory_order_relaxed);
    connections->statistics_.total_response_time_ms.fetch_add(total_resp_time, std::memory_order_relaxed);
    
    common::log.debug("aggregated stats for connections %s: req=%llu, succ=%llu, fail=%llu, avg_time=%lldms",
                      connections->data_.uri.c_str(),
                      (unsigned long long)total_req, (unsigned long long)total_succ, (unsigned long long)total_fail,
                      total_req > 0 ? (long long)(total_resp_time / total_req) : 0LL);
  }
  
  // Then, remove closed upstreams and perform health checks
  size_t removed_count = 0;
  for (auto it = instances_to_check.begin(); it != instances_to_check.end();) {
    auto instance = *it;
    
    // Check if upstream is open
    bool is_open = co_await instance->is_open();
    if (!is_open) {
      // Remove closed instance
      std::lock_guard<std::mutex> lock(connections->mutex_);
      auto inst_it = std::find(connections->instances_.begin(), 
                               connections->instances_.end(), instance);
      if (inst_it != connections->instances_.end()) {
        connections->instances_.erase(inst_it);
        removed_count++;
      }
      it = instances_to_check.erase(it);
      continue;
    }
    
    // Perform health check if enabled
    if (instance->check_enabled()) {
      // Check time since last request
      auto last_request = instance->last_request_time();
      auto time_since_request = std::chrono::duration_cast<std::chrono::seconds>(
          now - last_request).count();
      
      // Perform health check if no request for check_interval seconds
      if (time_since_request >= instance->check_interval()) {
        // Perform health check using upstream->check() method
        try {
          bool check_passed = co_await instance->check();
          
          if (!check_passed) {
            co_await instance->close();
            // Health check failed
            // The connection should already be closed by check() on failure
            // It will be removed in the next check cycle
            common::log.warning("group '%s': health check failed for %s",
                                name().c_str(), connections->data_.uri.c_str());
          }
          
        } catch (const std::exception &e) {
          // Health check error
          common::log.warning("group '%s': health check error for %s: %s",
                              name().c_str(), connections->data_.uri.c_str(), e.what());
        }
      }
    }
    
    ++it;
  }
  
  if (removed_count > 0) {
    common::log.debug("group '%s': removed %zu closed/failed instances from connections %s",
                      name().c_str(), removed_count, connections->data_.uri.c_str());
  }
  
  // If all upstreams removed, switch to degraded
  if (connections->get_instance_count() == 0) {
    connections->status_ = connection_status::degraded;
    connections->status_change_time_ = now;
    connections->attempt_count_ = 0;
    common::log.warning("group '%s': connections %s switched to degraded (all instances closed/failed)",
                        name().c_str(), connections->data_.uri.c_str());
  }
}

// Recover degraded connections: attempt to create and open a new instance
asio::awaitable<void> dns_pool_group::recover_degraded_connections(
    std::shared_ptr<dns_pool_connections> connections,
    std::chrono::steady_clock::time_point now) {
  
  auto time_since_change = std::chrono::duration_cast<std::chrono::seconds>(
      now - connections->status_change_time_).count();
  auto time_since_attempt = std::chrono::duration_cast<std::chrono::seconds>(
      now - connections->last_attempt_time_).count();
  
  // Try every 15 seconds after status change
  if (time_since_change >= 15 && time_since_attempt >= 15) {
    connections->last_attempt_time_ = now;
    connections->attempt_count_++;
    
    common::log.debug("group '%s': attempting to recover degraded connections %s (attempt %zu/5)",
                      name().c_str(), connections->data_.uri.c_str(), 
                      connections->attempt_count_);
    
    auto instance = co_await connections->create_single_instance();
    if (instance) {
      // Successfully opened (validated in upstream->open for TLS/HTTPS)
      {
        std::lock_guard<std::mutex> lock(connections->mutex_);
        connections->instances_.push_back(instance);
      }
      connections->status_ = connection_status::active;
      connections->status_change_time_ = now;
      connections->attempt_count_ = 0;
      common::log.info("group '%s': connections %s recovered to active",
                       name().c_str(), connections->data_.uri.c_str());
      
      // Reset cumulative counters for fair competition after recovery
      reset_all_cumulative_counters();
    } else {
      if (connections->attempt_count_ >= 5) {
        connections->status_ = connection_status::offline;
        connections->status_change_time_ = now;
        connections->attempt_count_ = 0;
        common::log.warning("group '%s': connections %s switched to offline (5 failed attempts)",
                            name().c_str(), connections->data_.uri.c_str());
      }
    }
  }
}

// Recover offline connections: attempt to create and open a new instance
asio::awaitable<void> dns_pool_group::recover_offline_connections(
    std::shared_ptr<dns_pool_connections> connections,
    std::chrono::steady_clock::time_point now) {
  
  auto time_since_change = std::chrono::duration_cast<std::chrono::seconds>(
      now - connections->status_change_time_).count();
  auto time_since_attempt = std::chrono::duration_cast<std::chrono::seconds>(
      now - connections->last_attempt_time_).count();
  
  // Try every 120 seconds after status change
  if (time_since_change >= 120 && time_since_attempt >= 120) {
    connections->last_attempt_time_ = now;
    connections->attempt_count_++;
    
    common::log.debug("group '%s': attempting to recover offline connections %s (attempt %zu)",
                      name().c_str(), connections->data_.uri.c_str(), 
                      connections->attempt_count_);
    
    auto instance = co_await connections->create_single_instance();
    if (instance) {
      // Successfully opened (validated in upstream->open for TLS/HTTPS)
      {
        std::lock_guard<std::mutex> lock(connections->mutex_);
        connections->instances_.push_back(instance);
      }
      connections->status_ = connection_status::active;
      connections->status_change_time_ = now;
      connections->attempt_count_ = 0;
      common::log.info("group '%s': connections %s recovered from offline to active",
                       name().c_str(), connections->data_.uri.c_str());
      
      // Reset cumulative counters for fair competition after recovery
      reset_all_cumulative_counters();
    }
  }
}

std::shared_ptr<dns_pool_group>
dns_upstream_pool::create_group(const std::string &group_name) {
  return create_group(group_name, 0);
}

std::shared_ptr<dns_pool_group>
dns_upstream_pool::create_group(const std::string &group_name,
                                 size_t target_size) {
  std::lock_guard<std::mutex> lock(mutex_);

  // Check if group already exists
  auto it = groups_.find(group_name);
  if (it != groups_.end()) {
    common::log.warning("group '%s' already exists", group_name.c_str());
    return it->second;
  }

  // Create new group
  auto group = std::make_shared<dns_pool_group>(group_name, target_size,
                                                 executor_);
  groups_[group_name] = group;

  common::log.debug("created upstream group: %s (target_size: %zu)",
                    group_name.c_str(), target_size);
  return group;
}

std::shared_ptr<dns_pool_group>
dns_upstream_pool::get_group(const std::string &group_name) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = groups_.find(group_name);
  if (it != groups_.end()) {
    return it->second;
  }

  common::log.debug("group '%s' not found", group_name.c_str());
  return nullptr;
}

bool dns_upstream_pool::has_group(const std::string &group_name) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return groups_.find(group_name) != groups_.end();
}

asio::awaitable<bool>
dns_upstream_pool::remove_group(const std::string &group_name) {
  std::shared_ptr<dns_pool_group> group_to_remove;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = groups_.find(group_name);
    if (it == groups_.end()) {
      common::log.warning("cannot remove non-existent group '%s'",
                          group_name.c_str());
      co_return false;
    }

    group_to_remove = it->second;
    groups_.erase(it);

    // If it's the default group, clear default group setting
    if (default_group_ == group_to_remove) {
      default_group_ = nullptr;
    }
  }

  // Clear connections in group (execute outside lock)
  co_await group_to_remove->clear();

  common::log.debug("removed group '%s'", group_name.c_str());
  co_return true;
}

std::vector<std::string> dns_upstream_pool::get_all_group_names() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::string> names;
  names.reserve(groups_.size());

  for (const auto &pair : groups_) {
    names.push_back(pair.first);
  }

  return names;
}

size_t dns_upstream_pool::get_group_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return groups_.size();
}

size_t dns_upstream_pool::get_total_upstream_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  size_t total = 0;

  for (const auto &pair : groups_) {
    total += pair.second->get_total_instance_count();
  }

  return total;
}

asio::awaitable<void> dns_upstream_pool::clear_all() {
  std::vector<std::shared_ptr<dns_pool_group>> groups_to_clear;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &pair : groups_) {
      groups_to_clear.push_back(pair.second);
    }
    groups_.clear();
    default_group_ = nullptr;
  }

  // Clear all groups (execute outside lock)
  for (auto &group : groups_to_clear) {
    co_await group->clear();
  }

  common::log.debug("cleared all upstream groups from pool");
}

void dns_upstream_pool::set_default_group(const std::string &group_name) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = groups_.find(group_name);
  if (it != groups_.end()) {
    default_group_ = it->second;
    common::log.debug("set default group to '%s'", group_name.c_str());
  } else {
    common::log.warning("cannot set non-existent group '%s' as default",
                        group_name.c_str());
  }
}

std::shared_ptr<dns_pool_group> dns_upstream_pool::get_default_group() {
  std::lock_guard<std::mutex> lock(mutex_);
  return default_group_;
}

asio::awaitable<std::shared_ptr<dns_upstream>>
dns_upstream_pool::get_next_upstream(const std::string &group_name) {
  std::shared_ptr<dns_pool_group> group;
  
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = groups_.find(group_name);
    if (it != groups_.end()) {
      group = it->second;
    }
  }
  
  if (!group) {
    common::log.error("group not found: %s", group_name.c_str());
    co_return nullptr;
  }
  
  co_return co_await group->get_next_upstream();
}

// Monitoring method for HTTP API (const version)
std::shared_ptr<dns_pool_group>
dns_upstream_pool::get_group(const std::string &name) const {
  auto it = groups_.find(name);
  if (it != groups_.end()) {
    return it->second;
  }
  return nullptr;
}

// connection_statistics implementation
double connection_statistics::get_avg_response_time_ms() const {
  uint64_t total = total_requests.load(std::memory_order_relaxed);
  if (total == 0) {
    return 0.0;
  }
  
  int64_t total_time = total_response_time_ms.load(std::memory_order_relaxed);
  return static_cast<double>(total_time) / total;
}

double connection_statistics::get_success_rate() const {
  uint64_t total = total_requests.load(std::memory_order_relaxed);
  if (total == 0) {
    return 0.0;
  }
  
  uint64_t success = success_requests.load(std::memory_order_relaxed);
  return (static_cast<double>(success) / total) * 100.0;
}

void connection_statistics::reset() {
  total_requests.store(0, std::memory_order_relaxed);
  success_requests.store(0, std::memory_order_relaxed);
  failed_requests.store(0, std::memory_order_relaxed);
  total_response_time_ms.store(0, std::memory_order_relaxed);
}

} // namespace dns
