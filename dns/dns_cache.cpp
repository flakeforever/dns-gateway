//
// File: dns_cache.cpp
// Description: This file contains the implementation of...
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

#include "dns_cache.hpp"
#include <chrono>

namespace dns {
int64_t get_current_time() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

dns_cache_entry::dns_cache_entry()
    : create_time_(0), ttl_(0), access_count_(0) {}

uint32_t dns_cache_entry::get_ttl() {
  int elapsed_time = (dns::get_current_time() - create_time_) / 1000;
  int remaining_ttl = ttl_ - elapsed_time;

  // Ensure remaining TTL is at least 1
  if (remaining_ttl <= 0) {
    remaining_ttl = 1;
  }

  return remaining_ttl;
}

void dns_cache_entry::set_ttl(uint32_t value) { ttl_ = value; }

dns_cache::dns_cache(asio::any_io_executor executor) : executor_(executor) {
  last_update_time_ = dns::get_current_time();
}

bool dns_cache::init_cache(size_t max_cache) {
  // Create and allocate cache entries
  for (size_t i = 0; i < max_cache; i++) {
    dns_cache_entry *entry = new dns_cache_entry();
    free_cache_entries_.push_back(entry);
  }

  // Check if allocation was successful
  return (free_cache_entries_.size() == max_cache);
}

asio::awaitable<dns_cache_entry *> dns_cache::get_free_cache() {
  if (free_cache_entries_.empty()) {
    // Find the cache entry with the lowest weight
    std::string lowest_weight_key;
    double lowest_weight = std::numeric_limits<double>::max();

    for (const auto &entry : cache_entries_) {
      dns_cache_entry *cache_entry = entry.second;
      int elapsed_time =
          (dns::get_current_time() - cache_entry->create_time_) / 1000;
      double weight =
          static_cast<double>(cache_entry->access_count_) / (elapsed_time + 1);

      if (weight < lowest_weight) {
        lowest_weight = weight;
        lowest_weight_key = entry.first;
      }
    }

    // Remove the cache entry with the lowest weight
    if (!lowest_weight_key.empty()) {
      dns_cache_entry *removed_entry = cache_entries_[lowest_weight_key];

      common::log.debug("remove lowest weight entry %s",
                   removed_entry->domain_.c_str());

      cache_entries_.erase(lowest_weight_key);
      free_cache_entries_.push_back(removed_entry);
    }
  }

  if (free_cache_entries_.empty()) {
    // common::log.info("free cache is null");
    co_return nullptr; // No free cache entry available
  }

  // Get the first entry from free_cache_entries_
  dns_cache_entry *cache_entry = free_cache_entries_.front();

  // Remove it from free_cache_entries_
  free_cache_entries_.erase(free_cache_entries_.begin());
  co_return cache_entry;
}

asio::awaitable<void> dns_cache::add_cache(const std::string &domain,
                                           uint8_t type,
                                           dns_cache_entry *cache_entry) {
  std::string key = generate_key(domain, type);

  // Add cache entry to cache_ map
  if (cache_entries_.find(key) != cache_entries_.end()) {
    free_cache_entries_.push_back(cache_entries_[key]);
    cache_entries_[key] = cache_entry;
    common::log.debug("cache entry %s is exists", cache_entry->domain_.c_str());
  } else {
    cache_entries_[key] = cache_entry;
    common::log.debug("add cache entry %s", cache_entry->domain_.c_str());
  }

  co_return;
}

asio::awaitable<dns_cache_entry *>
dns_cache::query_cache(const std::string &domain, uint8_t type) {
  std::string key = generate_key(domain, type);

  // update cache
  co_await update();

  // Check if cache entry exists in cache_
  auto it = cache_entries_.find(key);
  if (it != cache_entries_.end()) {
    dns_cache_entry *cache_entry = it->second;

    cache_entry->access_count_++; // Increment access count
    common::log.debug("query cache entry %s", cache_entry->domain_.c_str());
    co_return cache_entry; // Return cache entry
  }

  co_return nullptr; // Cache entry not found
}

asio::awaitable<void> dns_cache::update() {
  int64_t current_time = dns::get_current_time();

  // Check if the time difference is less than 1000 milliseconds
  if (current_time - last_update_time_ < 1000) {
    co_return; // Skip update
  }

  last_update_time_ = current_time; // Update last_update_time

  std::vector<std::string> expired_entries; // Store expired cache entry keys

  // Iterate over cache_ map and check each cache entry
  for (auto &entry : cache_entries_) {
    dns_cache_entry *cache_entry = entry.second;

    // Check if cache entry has expired based on ttl
    if (current_time >= cache_entry->create_time_ + cache_entry->ttl_ * 1000) {
      common::log.debug("remove cache entry %s", cache_entry->domain_.c_str());
      // Add expired cache entry key to the list
      expired_entries.push_back(entry.first);
    }
  }

  // Remove expired cache entries from cache_ map and move them to free_cache_
  for (const auto &key : expired_entries) {
    dns_cache_entry *cache_entry = cache_entries_[key];
    free_cache_entries_.push_back(cache_entry);
    cache_entries_.erase(key);
  }
}

std::string dns_cache::generate_key(const std::string &domain, uint8_t type) {
  // Generate key based on domain and type
  return domain + "_" + std::to_string(type);
}
} // namespace dns