//
// File: dns_router.cpp
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

#include "dns_router.hpp"
#include "../common/log.hpp"

namespace dns {
// dns_upstream_group is now just an abstract routing identifier
// All upstream instance management is handled by dns_upstream_pool
dns_upstream_group::dns_upstream_group() {}

dns_router::dns_router(asio::any_io_executor executor) 
    : executor_(executor), mutex_(executor) {}

std::shared_ptr<dns_upstream_group>
dns_router::create_group(const std::string &name) {
  std::shared_ptr<dns_upstream_group> group =
      std::make_shared<dns::dns_upstream_group>();
  group->id(get_next_group_id());
  group->name(name);
  upstream_groups_[group->id()] = group;

  return upstream_groups_[group->id()];
}

std::shared_ptr<dns_upstream_group> dns_router::get_group(uint8_t group_id) {
  return upstream_groups_[group_id];
}

std::shared_ptr<dns_upstream_group>
dns_router::get_group(const std::string &name) {
  for (const auto &pair : upstream_groups_) {
    if (pair.second->name() == name) {
      return pair.second;
    }
  }

  return nullptr;
}

void dns_router::add_route(const std::string &domain, uint8_t group_id) {
  insert_to_trie(root_, domain, group_id);
}

asio::awaitable<uint8_t> dns_router::get_route(const std::string &domain) {
  async_mutex_lock lock(mutex_);
  co_await lock.get_lock();

  co_return search_in_trie(root_, domain);
}

asio::awaitable<std::string> dns_router::get_route_group_name(const std::string &domain) {
  // Get group id from route
  uint8_t group_id = co_await get_route(domain);
  
  // If no specific route found, try default group
  if (group_id == 0) {
    if (default_group) {
      common::log.debug("route: %s -> default group '%s'", 
                        domain.c_str(), default_group->name().c_str());
      co_return default_group->name();
    } else {
      common::log.warning("no route found for domain: %s (no default group)", 
                          domain.c_str());
      co_return "";
    }
  }
  
  // Get group by id
  auto group = get_group(group_id);
  if (group) {
    common::log.debug("route: %s -> matched group '%s' (id=%d)", 
                      domain.c_str(), group->name().c_str(), group_id);
    co_return group->name();
  }
  
  // Return empty string if no group found
  common::log.error("route: group_id %d not found for domain: %s", 
                    group_id, domain.c_str());
  co_return "";
}

uint8_t dns_router::get_next_group_id() { return next_group_id_++; }

void dns_router::insert_to_trie(trie_node *node, const std::string &domain,
                                uint8_t group_id) {
  for (int i = domain.length() - 1; i >= 0; --i) {
    char c = domain[i];
    if (!node->children.count(c)) {
      node->children[c] = new trie_node();
    }
    node = node->children[c];
  }
  node->group_id = group_id;
}

uint8_t dns_router::search_in_trie(trie_node *node, const std::string &domain) {
  for (int i = domain.length() - 1; i >= 0; --i) {
    char c = domain[i];
    if (node->children.count(c)) {
      node = node->children[c];
    } else {
      break;
    }
  }
  return node->group_id;
}
} // namespace dns
