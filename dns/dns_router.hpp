//
// File: dns_router.hpp
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

#include "dns_package.hpp"
#include "operation.hpp"
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace dns {
class dns_upstream_group_property {
  PROPERTY_READWRITE(uint8_t, id);
  PROPERTY_READWRITE(std::string, name);
};

// Abstract group definition for routing logic only
// Does not contain any upstream instances
class dns_upstream_group
    : public dns_upstream_group_property,
      public std::enable_shared_from_this<dns_upstream_group> {
public:
  dns_upstream_group();
};

class dns_router {
public:
  dns_router(asio::any_io_executor executor);

  std::shared_ptr<dns_upstream_group> create_group(const std::string &name);
  std::shared_ptr<dns_upstream_group> get_group(uint8_t group_id);
  std::shared_ptr<dns_upstream_group> get_group(const std::string &name);

  // add a route by domain and group_id
  void add_route(const std::string &domain, uint8_t group_id);
  // get upstream group id by domain
  asio::awaitable<uint8_t> get_route(const std::string &domain);
  // get upstream group name by domain
  asio::awaitable<std::string> get_route_group_name(const std::string &domain);

  std::shared_ptr<dns_upstream_group> default_group;

private:
  class trie_node {
  public:
    std::unordered_map<char, trie_node *> children;
    uint8_t group_id;

    trie_node() : group_id(0) {}
  };

  uint8_t get_next_group_id();
  void insert_to_trie(trie_node *node, const std::string &domain,
                      uint8_t group_id);
  uint8_t search_in_trie(trie_node *node, const std::string &domain);

  trie_node *root_ = new trie_node();
  std::unordered_map<uint8_t, std::shared_ptr<dns_upstream_group>>
      upstream_groups_;
  uint8_t next_group_id_ = 1;

  asio::any_io_executor executor_;
  async_mutex mutex_;
};
} // namespace dns
