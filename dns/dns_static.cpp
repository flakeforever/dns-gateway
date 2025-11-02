//
// File: dns_static.cpp
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

#include "dns_static.hpp"

namespace dns {
dns_statics::dns_statics(asio::any_io_executor executor)
    : executor_(executor), mutex_(executor) {}

void dns_statics::add_static_value(const std::string &domain,
                                   dns::anwser_type type,
                                   const std::string &value) {
  std::string key = generate_key(domain, type);
  static_values_[key].push_back(value);
}

asio::awaitable<std::vector<std::string>>
dns_statics::get_static_values(const std::string &domain,
                               dns::anwser_type type) {
  std::string key = generate_key(domain, type);

  auto it = static_values_.find(key);
  if (it != static_values_.end()) {
    co_return it->second;
  } else {
    co_return std::vector<std::string>();
  }
}

std::string dns_statics::generate_key(const std::string &domain,
                                      dns::anwser_type type) {
  return domain + "_" + std::to_string(static_cast<int>(type));
}
} // namespace dns