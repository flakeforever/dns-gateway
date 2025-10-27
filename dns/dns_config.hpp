//
// File: config.hpp
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

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace dns {
struct dns_upstream_data {
  std::string uri;
  bool security_verify = false;
  std::string ca_certificate = "";
  std::string certificate = "";
  std::string private_key = "";
  std::string proxy;
  bool keep_alive = false;
  bool check_enabled = false;
  int check_interval = 0;
  std::string check_domains = "";  // Comma-separated list of domains for health checks
};

struct dns_group_data {
  std::string name;
  bool is_default = false;
  int pools;
  std::vector<dns_upstream_data> upstreams;
};

struct dns_rule_data {
  std::string file;
  std::string group;
};

struct dns_static_data {
  std::string domain;
  std::string type;
  std::string value;
};

struct dns_route_data {
  std::vector<dns_rule_data> rules;
  std::vector<dns_static_data> statics;
};

class dns_config {
public:
  int min_pools;
  int max_pools;
  int max_cache;
  std::string protocol;
  std::string listen_address;
  int listen_port;
  int monitor_port;  // HTTP monitor API port
  std::string log_level;
  std::string config_dir;  // Directory where config file is located
  std::vector<dns_group_data> groups;
  std::vector<dns_route_data> routes;
};

bool load_config(const std::string &config_file, dns_config &config);
} // namespace config