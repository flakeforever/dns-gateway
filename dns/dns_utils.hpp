//
// File: dns_utils.hpp
// Description: DNS utility functions for URI parsing
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

#include <string>
#include <cstdint>

namespace dns {

// Default ports for DNS protocols
constexpr uint16_t DEFAULT_DNS_PORT = 53;
constexpr uint16_t DEFAULT_DOT_PORT = 853;
constexpr uint16_t DEFAULT_DOH_PORT = 443;

// URI scheme types
enum class uri_scheme {
  unknown,
  udp,
  tls,
  dot,
  https,
  doh
};

// Parsed upstream URI components
struct upstream_uri {
  uri_scheme scheme;
  std::string host;
  uint16_t port;
  std::string path;  // For HTTPS/DoH only
  
  upstream_uri() : scheme(uri_scheme::unknown), port(0), path("") {}
  
  bool is_valid() const { return scheme != uri_scheme::unknown && !host.empty(); }
};

// Parsed proxy URI components
struct proxy_uri {
  std::string type;  // "socks5", etc.
  std::string host;
  uint16_t port;
  
  proxy_uri() : port(0) {}
  
  bool is_valid() const { return !type.empty() && !host.empty() && port > 0; }
};

// Parse DNS upstream URI
// Supported formats:
//   - udp://host[:port]
//   - tls://host[:port]
//   - dot://host[:port]
//   - https://host[:port][/path]
//   - doh://host[:port][/path]
upstream_uri parse_upstream_uri(const std::string &uri);

// Parse proxy URI
// Supported formats:
//   - socks5://host:port
proxy_uri parse_proxy_uri(const std::string &uri);

// Get default port for a scheme
uint16_t get_default_port(uri_scheme scheme);

// Convert scheme enum to string
std::string scheme_to_string(uri_scheme scheme);

} // namespace dns

