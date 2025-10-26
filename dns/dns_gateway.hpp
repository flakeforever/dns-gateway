//
// File: dns_gateway.hpp
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
#include "dns_cache.hpp"
#include "dns_monitor.hpp"
#include "dns_object.hpp"
#include "dns_package.hpp"
#include "dns_router.hpp"
#include "dns_static.hpp"
#include "dns_upstream.hpp"
#include "dns_upstream_pool.hpp"
#include "operation.hpp"
#include "property.hpp"
#include <iostream>
#include <vector>

namespace dns {
constexpr int dns_port = 53;
constexpr int coroutine_timeout = 5000;

class dns_gateway_propery {
public:
  PROPERTY_READONLY(bool, terminated);
  PROPERTY_READONLY(bool, checker_started);
};

class dns_gateway : public dns_gateway_propery {
public:
  dns_gateway(asio::any_io_executor executor,
              asio::ip::udp::resolver::protocol_type protocol, uint16_t port,
              int min_pools, int max_pools, uint16_t monitor_port = 0);
  dns_gateway(asio::any_io_executor executor, std::string address,
              uint16_t port, int min_pools, int max_pools, uint16_t monitor_port = 0);

  asio::awaitable<void> start();
  void stop();
  asio::awaitable<void> run_process();

  dns_router &get_router();
  dns_statics &get_statics();
  dns_cache &get_cache();
  dns_upstream_pool &get_upstream_pool();
  dns_monitor &get_monitor();

  asio::awaitable<void> wait_terminated();
  asio::any_io_executor get_executor();

protected:
  asio::awaitable<int> do_receive();
  asio::awaitable<bool> handle_dns_static(dns::dns_object *dns_object);
  asio::awaitable<bool> handle_query_cache(dns::dns_object *dns_object);
  asio::awaitable<bool> handle_create_cache(dns::dns_object *dns_object);
  asio::awaitable<bool> handle_dns_request(dns::dns_object *dns_object);

private:
  asio::awaitable<bool>
  dns_upstream_request(std::shared_ptr<dns_upstream> dns_upstream,
                       dns::dns_object *dns_object);
  asio::awaitable<void>
  dns_upstream_close(std::shared_ptr<dns_upstream> dns_upstream);

  asio::any_io_executor executor_;
  uint16_t port_;
  uint16_t monitor_port_;
  asio::ip::udp::socket udp_socket_;
  dns_object_pool object_pool_;
  asio::ip::udp::endpoint remote_endpoint_;

  dns_router router_;
  dns_statics statics_;
  dns_cache cache_;
  dns_upstream_pool upstream_pool_;
  dns_monitor monitor_;
  
  char recv_buffer_[dns::buffer_size];
  char check_buffer_[dns::buffer_size];
  int object_id_;
  
  bool active_;
};
} // namespace dns
