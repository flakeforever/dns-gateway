//
// File: config.cpp
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

#include "dns_config.hpp"
#include "lib/json/single_include/nlohmann/json.hpp"
#include <sstream>

using json = nlohmann::json;

namespace dns {
bool load_config(const std::string &config_file, dns_config &config) {
  std::ifstream ifs(config_file);
  if (!ifs.is_open()) {
    std::cout << "Failed to open config file: " << config_file << std::endl;
    return false;
  }
  
  // Extract directory path from config file path
  size_t last_slash = config_file.find_last_of("/\\");
  if (last_slash != std::string::npos) {
    config.config_dir = config_file.substr(0, last_slash);
  } else {
    config.config_dir = ".";  // Current directory
  }

  // Parse the JSON file
  json obj;
  try {
    ifs >> obj;
  } catch (const json::parse_error& e) {
    std::cout << "Failed to parse JSON: " << e.what() << std::endl;
    return false;
  }

  // Extract the values from the JSON and populate the config object
  if (!obj.is_object()) {
    std::cout << "Invalid JSON format: expected an object" << std::endl;
    return false;
  }

  if (obj.contains("max_works") && obj["max_works"].is_number()) {
    config.max_works = obj["max_works"].get<int>();

    if (config.max_works <= 0) {
      std::cout << "Invalid config format: max_works cannot be set to \""
                << config.max_works << "\"." << std::endl;
      return false;
    }
  }
  if (obj.contains("max_pools") && obj["max_pools"].is_number()) {
    config.max_pools = obj["max_pools"].get<int>();
  }
  if (obj.contains("max_cache") && obj["max_cache"].is_number()) {
    config.max_cache = obj["max_cache"].get<int>();
  }
  if (obj.contains("protocol") && obj["protocol"].is_string()) {
    config.protocol = obj["protocol"].get<std::string>();
  }
  if (obj.contains("listen_address") && obj["listen_address"].is_string()) {
    config.listen_address = obj["listen_address"].get<std::string>();
  }
  if (obj.contains("listen_port") && obj["listen_port"].is_number()) {
    config.listen_port = obj["listen_port"].get<int>();
  }
  
  // Parse monitor_port (optional, default 0 means disabled)
  if (obj.contains("monitor_port") && obj["monitor_port"].is_number()) {
    config.monitor_port = obj["monitor_port"].get<int>();
  } else {
    config.monitor_port = 0;  // Disabled by default
  }
  
  if (obj.contains("log_level") && obj["log_level"].is_string()) {
    config.log_level = obj["log_level"].get<std::string>();
  }
  
  if (obj.contains("groups") && obj["groups"].is_array()) {
    const auto &groups_arr = obj["groups"];
    for (const auto &group_val : groups_arr) {
      if (group_val.is_object()) {
        const auto &group_obj = group_val;
        dns_group_data group;
        if (group_obj.contains("name") && group_obj["name"].is_string()) {
          group.name = group_obj["name"].get<std::string>();
        }
        if (group_obj.contains("default") && group_obj["default"].is_boolean()) {
          group.is_default = group_obj["default"].get<bool>();
        }
        if (group_obj.contains("pools") && group_obj["pools"].is_number()) {
          group.pools = group_obj["pools"].get<int>();
        }
        if (group_obj.contains("upstreams") && group_obj["upstreams"].is_array()) {
          const auto &upstreams_arr = group_obj["upstreams"];
          for (const auto &upstream_val : upstreams_arr) {
            if (upstream_val.is_object()) {
              const auto &upstream_obj = upstream_val;
              dns_upstream_data upstream;
              if (upstream_obj.contains("uri") && upstream_obj["uri"].is_string()) {
                upstream.uri = upstream_obj["uri"].get<std::string>();
              }
              if (upstream_obj.contains("keep_alive") && upstream_obj["keep_alive"].is_boolean()) {
                upstream.keep_alive = upstream_obj["keep_alive"].get<bool>();
              }
              if (upstream_obj.contains("security_verify") && upstream_obj["security_verify"].is_boolean()) {
                upstream.security_verify = upstream_obj["security_verify"].get<bool>();
              }
              if (upstream_obj.contains("proxy") && upstream_obj["proxy"].is_string()) {
                upstream.proxy = upstream_obj["proxy"].get<std::string>();
              }
              if (upstream_obj.contains("ca_certificate") && upstream_obj["ca_certificate"].is_string()) {
                upstream.ca_certificate = upstream_obj["ca_certificate"].get<std::string>();
              }
              if (upstream_obj.contains("certificate") && upstream_obj["certificate"].is_string()) {
                upstream.certificate = upstream_obj["certificate"].get<std::string>();
              }
              if (upstream_obj.contains("private_key") && upstream_obj["private_key"].is_string()) {
                upstream.private_key = upstream_obj["private_key"].get<std::string>();
              }
              if (upstream_obj.contains("check_enabled") && upstream_obj["check_enabled"].is_boolean()) {
                upstream.check_enabled = upstream_obj["check_enabled"].get<bool>();
              }
              if (upstream_obj.contains("check_interval") && upstream_obj["check_interval"].is_number()) {
                upstream.check_interval = upstream_obj["check_interval"].get<int>();
              }
              if (upstream_obj.contains("check_domains") && upstream_obj["check_domains"].is_string()) {
                upstream.check_domains = upstream_obj["check_domains"].get<std::string>();
              }
              group.upstreams.push_back(upstream);
            }
          }
        }
        config.groups.push_back(group);
      }
    }
  }
  
  if (obj.contains("routes") && obj["routes"].is_array()) {
    const auto &routes_arr = obj["routes"];
    for (const auto &route_val : routes_arr) {
      if (route_val.is_object()) {
        const auto &route_obj = route_val;
        dns_route_data route;
        if (route_obj.contains("rules") && route_obj["rules"].is_array()) {
          const auto &rules_arr = route_obj["rules"];
          for (const auto &rule_val : rules_arr) {
            if (rule_val.is_object()) {
              const auto &rule_obj = rule_val;
              dns_rule_data rule;
              if (rule_obj.contains("file") && rule_obj["file"].is_string()) {
                rule.file = rule_obj["file"].get<std::string>();
              }
              if (rule_obj.contains("group") && rule_obj["group"].is_string()) {
                rule.group = rule_obj["group"].get<std::string>();
              }
              route.rules.push_back(rule);
            }
          }
        }
        if (route_obj.contains("statics") && route_obj["statics"].is_array()) {
          const auto &statics_arr = route_obj["statics"];
          for (const auto &static_val : statics_arr) {
            if (static_val.is_object()) {
              const auto &static_obj = static_val;
              dns_static_data static_entry;
              if (static_obj.contains("domain") && static_obj["domain"].is_string()) {
                static_entry.domain = static_obj["domain"].get<std::string>();
              }
              if (static_obj.contains("type") && static_obj["type"].is_string()) {
                static_entry.type = static_obj["type"].get<std::string>();
              }
              if (static_obj.contains("value") && static_obj["value"].is_string()) {
                static_entry.value = static_obj["value"].get<std::string>();
              }
              route.statics.push_back(static_entry);
            }
          }
        }
        config.routes.push_back(route);
      }
    }
  }
  
  return true;
}

} // namespace dns
