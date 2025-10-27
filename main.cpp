//
// File: main.cpp
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

#include <common/log.hpp>
#include <dns/dns_config.hpp>
#include <dns/dns_gateway.hpp>
#include "version.hpp"
#include <asio.hpp>
#include <asio/signal_set.hpp>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <string>

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::redirect_error;
using asio::use_awaitable;
using common::log_level;

std::string config_file;
bool test_config = false;

bool parse_arguments(int argc, char *argv[]) {
  bool show_help = false;

  if (argc == 1) {
    std::cout
        << "Please provide some command-line arguments to run the program."
        << std::endl;
    std::cout << "Use the '--help' option to see the available options."
              << std::endl;
    return false;
  }

  static struct option long_options[] = {
      {"config", required_argument, nullptr, 'c'},
      {"help", no_argument, nullptr, 'h'},
      {"version", no_argument, nullptr, 'v'},
      {"test", no_argument, nullptr, 't'},
      {nullptr, 0, nullptr, 0}};

  int option;
  while ((option = getopt_long(argc, argv, "hvc:t", long_options, nullptr)) !=
         -1) {
    switch (option) {
    case 'c':
      config_file = optarg;
      break;
    case 'h':
      show_help = true;
      break;
    case 'v':
      std::cout << PROJECT_NAME << " " << PROJECT_VER << std::endl;
      return false;
    case 't':
      test_config = true;
      break;
    default:
      return false;
    }
  }

  if (show_help) {
    // std::cout << "Help message: " << std::endl;
    std::cout << PROJECT_NAME << " " << PROJECT_VER << std::endl;
    std::cout << "Usage: " << argv[0] << " [OPTIONS]" << std::endl;
    std::cout << "-c, --config <file>   Set configuration file" << std::endl;
    std::cout << "-h, --help            Display this help message" << std::endl;
    std::cout << "-v, --version         Display version information"
              << std::endl;
    std::cout << "-t, --test            Test configuration file" << std::endl;
    return false;
  }

  return true;
}

void print_config(const dns::dns_config &config) {
  // max_works is deprecated (using single-threaded io_context now)
  std::cout << "min_pools: " << config.min_pools << std::endl;
  std::cout << "max_pools: " << config.max_pools << std::endl;
  std::cout << "max_cache: " << config.max_cache << std::endl;

  if (config.listen_address != "") {
    std::cout << "listen_address: " << config.listen_address << std::endl;
  } else if (config.protocol != "") {
    std::cout << "protocol: " << config.protocol << std::endl;
  }

  std::cout << "listen_port: " << config.listen_port << std::endl;

  std::cout << "groups: " << std::endl;
  for (const auto &group : config.groups) {
    std::cout << "  name: " << group.name << std::endl;
    std::string is_default = group.is_default ? "true" : "false";
    std::cout << "  is_default: " << is_default << std::endl;

    std::cout << "  upstreams: " << std::endl;
    for (const auto &upstream : group.upstreams) {
      std::cout << "    uri: " << upstream.uri << std::endl;
      std::cout << "    proxy: " << upstream.proxy << std::endl;
      std::string check_enabled = upstream.check_enabled ? "true" : "false";
      std::cout << "    check_enabled: " << check_enabled << std::endl;
      std::cout << "    check_interval: " << upstream.check_interval
                << std::endl;
    }
  }

  std::cout << "routes: " << std::endl;
  for (const auto &route : config.routes) {
    std::cout << "  rules: " << std::endl;
    for (const auto &rule : route.rules) {
      std::cout << "    file: " << rule.file << std::endl;
      std::cout << "    group: " << rule.group << std::endl;
    }

    std::cout << "  statics: " << std::endl;
    for (const auto &static_entry : route.statics) {
      std::cout << "    domain: " << static_entry.domain << std::endl;
      std::cout << "    type: " << static_entry.type << std::endl;
      std::cout << "    value: " << static_entry.value << std::endl;
    }
  }
}

void init_logger(common::logger &log_instance, dns::dns_config config) {
  if (config.log_level == "error") {
    log_instance.level(log_level::error);
  } else if (config.log_level == "warning") {
    log_instance.level(log_level::warning);
  } else if (config.log_level == "info") {
    log_instance.level(log_level::info);
  } else if (config.log_level == "debug") {
    log_instance.level(log_level::debug);
  } else {
    log_instance.level(log_level::error);
  }
}

bool load_route(dns::dns_router &router, const std::string &file_name,
                const std::string &group_name, const std::string &config_dir) {
  // Resolve file path (support relative path to config directory)
  std::string resolved_path;
  if (file_name.empty()) {
    common::log.error("route file name is empty");
    return false;
  }
  
  // Check if it's an absolute path
  if (file_name[0] == '/' || 
      (file_name.length() >= 2 && file_name[1] == ':')) {  // Windows drive letter
    // Absolute path
    resolved_path = file_name;
  } else {
    // Relative path, resolve based on config directory
    resolved_path = config_dir + "/" + file_name;
  }
  
  std::ifstream file(resolved_path);
  if (!file) {
    common::log.error("failed to open route file: %s (resolved: %s)", 
                      file_name.c_str(), resolved_path.c_str());
    return false;
  }

  std::shared_ptr<dns::dns_upstream_group> group = router.get_group(group_name);
  if (!group) {
    common::log.error("route group not found: %s", group_name.c_str());
    return false;
  }

  common::log.info("loading routes from %s to group '%s' (id=%d)", 
                   resolved_path.c_str(), group_name.c_str(), group->id());

  int route_count = 0;
  std::string line;
  while (std::getline(file, line)) {
    // Trim whitespace
    line.erase(0, line.find_first_not_of(" \t\r\n"));
    line.erase(line.find_last_not_of(" \t\r\n") + 1);
    
    // Skip empty lines and comments
    if (!line.empty() && line[0] != '#') {
      router.add_route(line, group->id());
      route_count++;
      if (route_count <= 5) {
        common::log.debug("  added route: %s -> group '%s'", 
                          line.c_str(), group_name.c_str());
      }
    }
  }

  common::log.info("loaded %d routes to group '%s'", route_count, group_name.c_str());
  return true;
}

dns::dns_gateway *create_gateway(asio::any_io_executor executor, dns::dns_config config) {
  if (config.listen_address == "") {
    if (config.protocol == "ipv4") {
      return new dns::dns_gateway(executor, asio::ip::udp::v4(),
                                  config.listen_port, config.min_pools,
                                  config.max_pools, config.monitor_port);
    } else if (config.protocol == "ipv6") {
      return new dns::dns_gateway(executor, asio::ip::udp::v6(),
                                  config.listen_port, config.min_pools,
                                  config.max_pools, config.monitor_port);
    }
  } else {
    return new dns::dns_gateway(executor, config.listen_address,
                                config.listen_port, config.min_pools,
                                config.max_pools, config.monitor_port);
  }

  return nullptr;
}

asio::awaitable<bool> init_gateway(dns::dns_gateway *gateway,
                                    dns::dns_config &config) {
  dns::dns_router &router = gateway->get_router();

  if (!gateway->get_cache().init_cache(config.max_cache)) {
    co_return false;
  }

  // Get upstream_pool reference
  dns::dns_upstream_pool &upstream_pool = gateway->get_upstream_pool();

  for (const auto &group : config.groups) {
    // Create router group (for routing only, no upstream instances)
    std::shared_ptr<dns::dns_upstream_group> router_group =
        router.create_group(group.name);

    if (group.is_default) {
      router.default_group = router_group;
    }

    // Create pool_group with target_size from config.pools
    auto pool_group = upstream_pool.create_group(group.name, group.pools);
    
    if (group.is_default) {
      upstream_pool.set_default_group(group.name);
    }

    common::log.debug("initializing group: %s (target_size: %d)", 
                      group.name.c_str(), group.pools);

    // Add connections to pool_group (no upstream instances created yet)
    for (const auto &upstream : group.upstreams) {
      if (upstream.proxy.empty()) {
        common::log.debug("  connections: %s", upstream.uri.c_str());
      } else {
        common::log.debug("  connections: %s proxy: %s", 
                          upstream.uri.c_str(), upstream.proxy.c_str());
      }

      // Create dns_upstream_data
      dns::dns_upstream_data data;
      data.uri = upstream.uri;
      data.security_verify = upstream.security_verify;
      data.ca_certificate = upstream.ca_certificate;
      data.certificate = upstream.certificate;
      data.private_key = upstream.private_key;
      data.proxy = upstream.proxy;
      data.keep_alive = upstream.keep_alive;
      data.check_enabled = upstream.check_enabled;
      data.check_interval = upstream.check_interval;

      // Add connections to pool_group (will create instances during init)
      pool_group->add_upstream(data);
    }
  }

  for (const auto &route : config.routes) {
    for (const auto &rule : route.rules) {
      bool loaded = load_route(gateway->get_router(), rule.file, rule.group, 
                               config.config_dir);
      if (!loaded) {
        common::log.warning("failed to load route file '%s' for group '%s'",
                            rule.file.c_str(), rule.group.c_str());
      }
    }
    for (const auto &static_entry : route.statics) {
      if (static_entry.type == "A") {
        gateway->get_statics().add_static_value(
            static_entry.domain, dns::anwser_type::a, static_entry.value);
      } else if (static_entry.type == "AAAA") {
        gateway->get_statics().add_static_value(
            static_entry.domain, dns::anwser_type::aaaa, static_entry.value);
      } else if (static_entry.type == "CNAME") {
        gateway->get_statics().add_static_value(
            static_entry.domain, dns::anwser_type::cname, static_entry.value);
      } else if (static_entry.type == "TXT") {
        gateway->get_statics().add_static_value(
            static_entry.domain, dns::anwser_type::txt, static_entry.value);
      }
    }
  }

  co_return true;
}

int main(int argc, char *argv[]) {
  try {
    dns::dns_config config;
    if (!parse_arguments(argc, argv)) {
      return EXIT_FAILURE;
    }

    if (!dns::load_config(config_file, config)) {
      return EXIT_FAILURE;
    }

    if (test_config) {
      print_config(config);
      return 0;
    }

    init_logger(common::log, config);

    // Use single-threaded io_context instead of thread_pool
    asio::io_context io_context;
    asio::signal_set signals(io_context, SIGINT, SIGTERM);
    dns::dns_gateway *gateway =
        create_gateway(io_context.get_executor(), config);

    // set signals
    co_spawn(
        io_context,
        [&]() -> asio::awaitable<void> {
          co_await signals.async_wait(asio::use_awaitable);

          gateway->stop();
          co_await gateway->wait_terminated();

          io_context.stop();
        },
        detached);

    // handle process
    auto handle_process = [&]() -> asio::awaitable<void> {
      bool status = co_await init_gateway(gateway, config);

      if (status) {
        // Initialize gateway (sets active, initializes upstream pool, starts checker)
        co_await gateway->start();
        co_await gateway->run_process();
      } else {
        common::log.error("Failed to initialize dns-gateway.");
      }
    };

    // start dns gateway
    co_spawn(io_context, handle_process, detached);
    
    // Run the event loop (blocks until io_context.stop() is called)
    io_context.run();

    return 0;
  } catch (std::exception &e) {
    common::log.error("Exception: %s", e.what());
  }

  return 0;
}
