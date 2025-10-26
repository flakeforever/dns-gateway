//
// File: socks_common.cpp
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

#include "socks_common.hpp"

namespace socks {
address_type get_address_type(const std::string &address) {
  sockaddr_in sa4;
  sockaddr_in6 sa6;
  if (inet_pton(AF_INET, address.c_str(), &(sa4.sin_addr)) == 1) {
    return address_type::ipv4;
  } else if (inet_pton(AF_INET6, address.c_str(), &(sa6.sin6_addr)) == 1) {
    return address_type::ipv6;
  } else {
    return address_type::domain;
  }
}
} // namespace socks