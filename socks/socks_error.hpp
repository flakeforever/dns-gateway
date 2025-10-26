//
// File: socks_error.cpp
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

#include <system_error>

namespace socks {
namespace errc {
enum class error_code {
  unsupported_version = 1000,
  unsupported_authentication_method,
  unsupported_authentication_version,
  authentication_error,

  general_socks_server_failure,
  connection_not_allowed_by_ruleset,
  network_unreachable,
  host_unreachable,
  connection_refused,
  ttl_expired,
  command_not_supported,
  address_type_not_supported,
  unassigned,

  udp_data_error,
  remote_data_error,
  buffer_overflow,
  unknown_error,
};

class socks_error_category_impl : public std::error_category {
public:
  const char *name() const noexcept override;
  std::string message(int ev) const noexcept override;
};

std::error_code make_error_code(socks::errc::error_code ec);
} // namespace errc
} // namespace socks