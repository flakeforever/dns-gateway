//
// File: socks_common.hpp
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

#include <arpa/inet.h>
#include <string>

namespace socks {
enum class address_type {
  none = 0,
  ipv4 = 1,
  domain = 3,
  ipv6 = 4,
};

address_type get_address_type(const std::string &address);
} // namespace socks