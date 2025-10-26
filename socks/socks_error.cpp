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

#include "socks_error.hpp"

namespace socks {
namespace errc {
const std::error_category &socks_error_category() {
  static socks_error_category_impl instance;
  return instance;
}

std::error_code make_error_code(socks::errc::error_code ec) {
  return std::error_code(static_cast<int>(ec), socks_error_category());
}

const char *socks_error_category_impl::name() const noexcept {
  return "socks_error_category";
}

std::string socks_error_category_impl::message(int ev) const noexcept {
  switch (static_cast<error_code>(ev)) {
  case error_code::unsupported_version:
    return "Unsupported SOCKS version";
  case error_code::unsupported_authentication_method:
    return "Unsupported authentication method";
  case error_code::unsupported_authentication_version:
    return "Unsupported authentication version";
  case error_code::authentication_error:
    return "Authentication error";
  case error_code::general_socks_server_failure:
    return "General SOCKS server failure";
  case error_code::connection_not_allowed_by_ruleset:
    return "Connection not allowed by ruleset";
  case error_code::network_unreachable:
    return "Network unreachable";
  case error_code::host_unreachable:
    return "Host unreachable";
  case error_code::connection_refused:
    return "Connection refused";
  case error_code::ttl_expired:
    return "TTL expired";
  case error_code::command_not_supported:
    return "Command not supported";
  case error_code::address_type_not_supported:
    return "Address type not supported";
  case error_code::unassigned:
    return "Unassigned error code";
  case error_code::udp_data_error:
    return "UDP data error";
  case error_code::remote_data_error:
    return "Remote data error";
  case error_code::buffer_overflow:
    return "Buffer overflow";
  case error_code::unknown_error:
    return "Unknown error";
  }

  return "Unknown error: " + std::to_string(ev);
}
} // namespace errc
} // namespace socks