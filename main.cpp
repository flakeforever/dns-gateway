//
// File: main.cpp
// Description: This file contains the implementation of...
//
// Copyright (c) 2003-2023 The DNS-Gateway Authors.
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// This project uses the Asio library (https://think-async.com/Asio/) under the Boost Software License (https://www.boost.org/LICENSE_1_0.txt).
// This project uses OpenSSL (https://www.openssl.org) under the OpenSSL License (https://www.openssl.org/source/license.html).
//

#include <iostream>
#include <fstream>
#include <getopt.h>
#include <string>
#include <asio.hpp>
#include <asio/signal_set.hpp>
#include "lib/picojson/picojson.h"
#include "lib/CxxUrl/url.hpp"
#include "dns/dns_gateway.hpp"
#include "dns/dns_log.hpp"
#include "config.hpp"
#include "version.hpp"

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::redirect_error;
using asio::use_awaitable;

std::string config_file;
bool test_config = false;

bool parse_arguments(int argc, char *argv[])
{
    bool show_help = false;

    if (argc == 1)
    {
        std::cout << "Please provide some command-line arguments to run the program." << std::endl;
        std::cout << "Use the '--help' option to see the available options." << std::endl;
        return false;
    }

    static struct option long_options[] = {
        {"config", required_argument, nullptr, 'c'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'v'},
        {"test", no_argument, nullptr, 't'},
        {nullptr, 0, nullptr, 0}};

    int option;
    while ((option = getopt_long(argc, argv, "hvc:t", long_options, nullptr)) != -1)
    {
        switch (option)
        {
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

    if (show_help)
    {
        // std::cout << "Help message: " << std::endl;
        std::cout << PROJECT_NAME << " " << PROJECT_VER << std::endl;
        std::cout << "Usage: " << argv[0] << " [OPTIONS]" << std::endl;
        std::cout << "-c, --config <file>   Set configuration file" << std::endl;
        std::cout << "-h, --help            Display this help message" << std::endl;
        std::cout << "-v, --version         Display version information" << std::endl;
        std::cout << "-t, --test            Test configuration file" << std::endl;
        return false;
    }

    return true;
}

void print_config(const config::dns_config &config)
{
    std::cout << "max_works: " << config.max_works << std::endl;
    std::cout << "min_pools: " << config.min_pools << std::endl;
    std::cout << "max_pools: " << config.max_pools << std::endl;
    std::cout << "max_cache: " << config.max_cache << std::endl;

    if (config.listen_address != "")
    {
        std::cout << "listen_address: " << config.listen_address << std::endl;
    }
    else if (config.protocol != "")
    {
        std::cout << "protocol: " << config.protocol << std::endl;
    }

    std::cout << "listen_port: " << config.listen_port << std::endl;

    std::cout << "groups: " << std::endl;
    for (const auto &group : config.groups)
    {
        std::cout << "  name: " << group.name << std::endl;
        std::string is_default = group.is_default ? "true" : "false";
        std::cout << "  is_default: " << is_default << std::endl;

        std::cout << "  upstreams: " << std::endl;
        for (const auto &upstream : group.upstreams)
        {
            std::cout << "    uri: " << upstream.uri << std::endl;
            std::cout << "    proxy: " << upstream.proxy << std::endl;
            std::string check_enabled = upstream.check_enabled ? "true" : "false";
            std::cout << "    check_enabled: " << check_enabled << std::endl;
            std::cout << "    check_interval: " << upstream.check_interval << std::endl;
        }
    }

    std::cout << "routes: " << std::endl;
    for (const auto &route : config.routes)
    {
        std::cout << "  rules: " << std::endl;
        for (const auto &rule : route.rules)
        {
            std::cout << "    file: " << rule.file << std::endl;
            std::cout << "    group: " << rule.group << std::endl;
        }

        std::cout << "  statics: " << std::endl;
        for (const auto &static_entry : route.statics)
        {
            std::cout << "    domain: " << static_entry.domain << std::endl;
            std::cout << "    type: " << static_entry.type << std::endl;
            std::cout << "    value: " << static_entry.value << std::endl;
        }
    }

    std::cout << "check_domains: " << std::endl;
    for (const auto &domain : config.check_domains)
    {
        std::cout << "  [" << domain << "]" << std::endl;
    }
}

void init_logger(dns::dns_logger &logger, config::dns_config config)
{
    if (config.log_level == "error")
    {
        logger.level(dns::log_level::error);
    }
    else if (config.log_level == "warning")
    {
        logger.level(dns::log_level::warning);
    }
    else if (config.log_level == "info")
    {
        logger.level(dns::log_level::info);
    }
    else if (config.log_level == "debug")
    {
        logger.level(dns::log_level::debug);
    }
    else
    {
        logger.level(dns::log_level::error);
    }
}

bool load_route(dns::dns_router &router, const std::string &file_name, const std::string &group_name)
{
    std::ifstream file(file_name);
    if (!file)
    {
        dns::logger.error("Failed to open file: %s", file_name.c_str());
        return false;
    }

    std::shared_ptr<dns::dns_upstream_group> group = router.get_group(group_name);
    if (!group)
    {
        dns::logger.error("Group not found: %s", group_name.c_str());
        return false;
    }

    std::string line;
    while (std::getline(file, line))
    {
        if (!line.empty())
        {
            router.add_route(line, group->id());
        }
    }

    return true;
}

dns::dns_gateway *create_gateway(asio::any_io_executor executor, config::dns_config config)
{
    if (config.listen_address == "")
    {
        if (config.protocol == "ipv4")
        {
            return new dns::dns_gateway(executor, asio::ip::udp::v4(),
                                        config.listen_port, config.min_pools, config.max_pools);
        }
        else if (config.protocol == "ipv6")
        {
            return new dns::dns_gateway(executor, asio::ip::udp::v6(),
                                        config.listen_port, config.min_pools, config.max_pools);
        }
    }
    else
    {
        return new dns::dns_gateway(executor, config.listen_address,
                                    config.listen_port, config.min_pools, config.max_pools);
    }

    return nullptr;
}

asio::awaitable<bool> init_gateway(dns::dns_gateway *gateway, config::dns_config config)
{
    dns::dns_router &router = gateway->get_router();

    if (!gateway->get_cache().init_cache(config.max_cache))
    {
        co_return false;
    }

    for (const auto &domain : config.check_domains)
    {
        gateway->check_domains.push_back(domain);
    }

    for (const auto &group : config.groups)
    {
        std::shared_ptr<dns::dns_upstream_group> upstream_group = router.create_group(group.name);

        if (group.is_default)
        {
            router.default_group = upstream_group;
        }

        dns::logger.debug("upstream_group: %s", group.name.c_str());
        for (const auto &upstream : group.upstreams)
        {
            if (upstream.proxy == "")
            {
                dns::logger.debug("upstream: %s", upstream.uri.c_str());
            }
            else
            {
                dns::logger.debug("upstream: %s proxy: %s", upstream.uri.c_str(), upstream.proxy.c_str());
            }

            Url uri(upstream.uri);

            if (uri.scheme() == "udp")
            {
                uint16_t port = 53;

                if (uri.port() != "")
                {
                    port = std::stoi(uri.port());
                }

                std::shared_ptr<dns::dns_udp_upstream> udp_upstream =
                    std::make_shared<dns::dns_udp_upstream>(gateway->get_executor(), uri.host(), port);

                if (upstream.proxy != "")
                {
                    Url proxy_uri(upstream.proxy);
                    if (proxy_uri.scheme() == "socks5")
                    {
                        uint16_t proxy_port = std::stoi(proxy_uri.port());
                        udp_upstream->set_proxy(socks::proxy_type::socks5, proxy_uri.host(), proxy_port);
                    }
                }

                udp_upstream->check_enabled(upstream.check_enabled);
                udp_upstream->check_interval(upstream.check_interval);

                upstream_group->add_upstream(udp_upstream);
                gateway->upstreams_.push_back(udp_upstream);
            }
            else if (uri.scheme() == "dot")
            {
                uint16_t port = 853;

                if (uri.port() != "")
                {
                    port = std::stoi(uri.port());
                }

                std::shared_ptr<dns::dns_tls_upstream> tls_upstream =
                    std::make_shared<dns::dns_tls_upstream>(gateway->get_executor(), uri.host(), port);

                if (upstream.proxy != "")
                {
                    Url proxy_uri(upstream.proxy);
                    if (proxy_uri.scheme() == "socks5")
                    {
                        uint16_t proxy_port = std::stoi(proxy_uri.port());
                        tls_upstream->set_proxy(socks::proxy_type::socks5, proxy_uri.host(), proxy_port);
                    }
                }

                // tls_upstream->keep_alive(upstream.keep_alive);
                tls_upstream->security_verify(upstream.security_verify);
                tls_upstream->ca_certificate(upstream.ca_certificate);
                tls_upstream->certificate(upstream.certificate);
                tls_upstream->private_key(upstream.private_key);

                tls_upstream->check_enabled(upstream.check_enabled);
                tls_upstream->check_interval(upstream.check_interval);

                upstream_group->add_upstream(tls_upstream);
                gateway->upstreams_.push_back(tls_upstream);
            }
            else if (uri.scheme() == "doh")
            {
                uint16_t port = 443;

                if (uri.port() != "")
                {
                    port = std::stoi(uri.port());
                }

                std::shared_ptr<dns::dns_https_upstream> https_upstream =
                    std::make_shared<dns::dns_https_upstream>(
                        gateway->get_executor(), uri.host(), port, upstream.uri);

                if (upstream.proxy != "")
                {
                    Url proxy_uri(upstream.proxy);
                    if (proxy_uri.scheme() == "socks5")
                    {
                        uint16_t proxy_port = std::stoi(proxy_uri.port());
                        https_upstream->set_proxy(socks::proxy_type::socks5, proxy_uri.host(), proxy_port);
                    }
                }

                https_upstream->security_verify(upstream.security_verify);
                https_upstream->ca_certificate(upstream.ca_certificate);
                https_upstream->certificate(upstream.certificate);
                https_upstream->private_key(upstream.private_key);

                https_upstream->check_enabled(upstream.check_enabled);
                https_upstream->check_interval(upstream.check_interval);

                upstream_group->add_upstream(https_upstream);
                gateway->upstreams_.push_back(https_upstream);
            }
        }
    }

    for (const auto &route : config.routes)
    {
        for (const auto &rule : route.rules)
        {
            load_route(gateway->get_router(), rule.file, rule.group);
        }
        for (const auto &static_entry : route.statics)
        {
            if (static_entry.type == "A")
            {
                gateway->get_statics().add_static_value(
                    static_entry.domain, dns::anwser_type::a, static_entry.value);
            }
            if (static_entry.type == "AAAA")
            {
                gateway->get_statics().add_static_value(
                    static_entry.domain, dns::anwser_type::aaaa, static_entry.value);
            }
            if (static_entry.type == "CNAME")
            {
                gateway->get_statics().add_static_value(
                    static_entry.domain, dns::anwser_type::cname, static_entry.value);
            }
            if (static_entry.type == "TXT")
            {
                gateway->get_statics().add_static_value(
                    static_entry.domain, dns::anwser_type::txt, static_entry.value);
            }
        }
    }

    co_return true;
}

int main(int argc, char *argv[])
{
    try
    {
        config::dns_config config;
        if (!parse_arguments(argc, argv))
        {
            return EXIT_FAILURE;
        }

        if (!config::load_config(config_file, config))
        {
            return EXIT_FAILURE;
        }

        if (test_config)
        {
            print_config(config);
            return 0;
        }

        init_logger(dns::logger, config);

        asio::thread_pool thread_pool(config.max_works);
        asio::signal_set signals(thread_pool.get_executor(), SIGINT, SIGTERM);
        dns::dns_gateway *gateway = create_gateway(thread_pool.get_executor(), config);

        // set signals
        co_spawn(
            thread_pool.get_executor(),
            [&]() -> asio::awaitable<void>
            {
                co_await signals.async_wait(asio::use_awaitable);

                gateway->active(false);
                co_await gateway->wait_terminated();

                thread_pool.stop();
            },
            detached);

        // handle process
        auto handle_process = [&]() -> asio::awaitable<void>
        {
            bool status = co_await init_gateway(gateway, config);

            if (status)
            {
                dns::logger.info("dns-gateway is running.");

                gateway->active(true);
                co_await gateway->run_process();
            }
            else
            {
                dns::logger.error("Failed to initialize dns-gateway.");
            }
        };

        // start dns gateway
        co_spawn(thread_pool.get_executor(), handle_process, detached);
        thread_pool.join();

        return 0;
    }
    catch (std::exception &e)
    {
        dns::logger.error("Exception: %s", e.what());
    }

    return 0;
}
