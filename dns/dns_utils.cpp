//
// File: dns_utils.cpp
// Description: DNS utility functions implementation
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

#include "dns_utils.hpp"
#include "../common/log.hpp"
#include <algorithm>

namespace dns {

uint16_t get_default_port(uri_scheme scheme) {
  switch (scheme) {
    case uri_scheme::udp:
      return DEFAULT_DNS_PORT;
    case uri_scheme::tls:
    case uri_scheme::dot:
      return DEFAULT_DOT_PORT;
    case uri_scheme::https:
    case uri_scheme::doh:
      return DEFAULT_DOH_PORT;
    default:
      return 0;
  }
}

std::string scheme_to_string(uri_scheme scheme) {
  switch (scheme) {
    case uri_scheme::udp: return "udp";
    case uri_scheme::tls: return "tls";
    case uri_scheme::dot: return "dot";
    case uri_scheme::https: return "https";
    case uri_scheme::doh: return "doh";
    default: return "unknown";
  }
}

upstream_uri parse_upstream_uri(const std::string &uri) {
  upstream_uri result;
  
  if (uri.empty()) {
    common::log.error("empty URI");
    return result;
  }
  
  // Find scheme separator
  size_t scheme_sep = uri.find("://");
  if (scheme_sep == std::string::npos) {
    common::log.error("invalid URI format (missing '://'): %s", uri.c_str());
    return result;
  }
  
  // Extract and parse scheme
  std::string scheme_str = uri.substr(0, scheme_sep);
  std::transform(scheme_str.begin(), scheme_str.end(), scheme_str.begin(), ::tolower);
  
  if (scheme_str == "udp") {
    result.scheme = uri_scheme::udp;
  } else if (scheme_str == "tls") {
    result.scheme = uri_scheme::tls;
  } else if (scheme_str == "dot") {
    result.scheme = uri_scheme::dot;
  } else if (scheme_str == "https") {
    result.scheme = uri_scheme::https;
  } else if (scheme_str == "doh") {
    result.scheme = uri_scheme::doh;
  } else {
    common::log.error("unsupported URI scheme '%s' in: %s", scheme_str.c_str(), uri.c_str());
    return result;
  }
  
  // Extract the rest after "://"
  std::string rest = uri.substr(scheme_sep + 3);
  
  if (rest.empty()) {
    common::log.error("missing host in URI: %s", uri.c_str());
    return result;
  }
  
  // For HTTPS/DoH, extract path
  if (result.scheme == uri_scheme::https || result.scheme == uri_scheme::doh) {
    size_t path_pos = rest.find('/');
    if (path_pos != std::string::npos) {
      result.path = rest.substr(path_pos);
      rest = rest.substr(0, path_pos);
    } else {
      result.path = "/dns-query";  // Default path for DoH
    }
  }
  
  // Parse host:port
  size_t colon_pos = rest.find(':');
  if (colon_pos != std::string::npos) {
    // Has explicit port
    result.host = rest.substr(0, colon_pos);
    std::string port_str = rest.substr(colon_pos + 1);
    
    try {
      int port_val = std::stoi(port_str);
      if (port_val <= 0 || port_val > 65535) {
        common::log.error("invalid port '%s' in URI: %s", port_str.c_str(), uri.c_str());
        result.scheme = uri_scheme::unknown;
        return result;
      }
      result.port = static_cast<uint16_t>(port_val);
    } catch (const std::exception &e) {
      common::log.error("failed to parse port '%s' in URI: %s", port_str.c_str(), uri.c_str());
      result.scheme = uri_scheme::unknown;
      return result;
    }
  } else {
    // No explicit port, use default
    result.host = rest;
    result.port = get_default_port(result.scheme);
  }
  
  if (result.host.empty()) {
    common::log.error("empty host in URI: %s", uri.c_str());
    result.scheme = uri_scheme::unknown;
    return result;
  }
  
  return result;
}

proxy_uri parse_proxy_uri(const std::string &uri) {
  proxy_uri result;
  
  if (uri.empty()) {
    return result;
  }
  
  // Find scheme separator
  size_t scheme_sep = uri.find("://");
  if (scheme_sep == std::string::npos) {
    common::log.error("invalid proxy URI format (missing '://'): %s", uri.c_str());
    return result;
  }
  
  // Extract proxy type
  result.type = uri.substr(0, scheme_sep);
  std::transform(result.type.begin(), result.type.end(), result.type.begin(), ::tolower);
  
  // Currently only support socks5
  if (result.type != "socks5") {
    common::log.error("unsupported proxy type '%s' in: %s", result.type.c_str(), uri.c_str());
    result.type.clear();
    return result;
  }
  
  // Extract host:port
  std::string rest = uri.substr(scheme_sep + 3);
  size_t colon_pos = rest.find(':');
  
  if (colon_pos == std::string::npos) {
    common::log.error("missing port in proxy URI: %s", uri.c_str());
    result.type.clear();
    return result;
  }
  
  result.host = rest.substr(0, colon_pos);
  std::string port_str = rest.substr(colon_pos + 1);
  
  try {
    int port_val = std::stoi(port_str);
    if (port_val <= 0 || port_val > 65535) {
      common::log.error("invalid port '%s' in proxy URI: %s", port_str.c_str(), uri.c_str());
      result.type.clear();
      return result;
    }
    result.port = static_cast<uint16_t>(port_val);
  } catch (const std::exception &e) {
    common::log.error("failed to parse port '%s' in proxy URI: %s", port_str.c_str(), uri.c_str());
    result.type.clear();
    return result;
  }
  
  if (result.host.empty()) {
    common::log.error("empty host in proxy URI: %s", uri.c_str());
    result.type.clear();
    return result;
  }
  
  return result;
}

} // namespace dns

