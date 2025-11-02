//
// File: dns_cache.hpp
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

#pragma once

#include "../common/log.hpp"
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
// #include <message.h>
#include "dns_package.hpp"
#include "operation.hpp"

namespace dns {
const int max_ttl_time = 60; // seconds

int64_t get_current_time();

class dns_cache_entry {
public:
  dns_cache_entry();

  uint32_t get_ttl();
  void set_ttl(uint32_t value);

  std::string domain_;
  int64_t create_time_;
  uint32_t ttl_;
  size_t access_count_;

  char buffer_[dns::buffer_size];
  uint16_t buffer_size_;
};

class dns_cache {
public:
  dns_cache(asio::any_io_executor executor);

  bool init_cache(size_t max_cache);

  asio::awaitable<dns_cache_entry *> get_free_cache();
  asio::awaitable<void> add_cache(const std::string &domain, uint8_t type,
                                  dns_cache_entry *cache_entry);
  asio::awaitable<dns_cache_entry *> query_cache(const std::string &domain,
                                                 uint8_t type);

  async_mutex mutex_;

private:
  std::string generate_key(const std::string &domain, uint8_t type);
  asio::awaitable<void> update();

  std::vector<dns_cache_entry *> free_cache_entries_;
  std::map<std::string, dns_cache_entry *> cache_entries_;
  int64_t last_update_time_;

  asio::any_io_executor executor_;
};
} // namespace dns
