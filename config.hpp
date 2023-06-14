//
// File: config.hpp
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

#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

namespace config
{
    struct dns_upstream
    {
        std::string uri;
        std::string proxy;
        bool keep_alive = false;
        bool check_enabled = false;
        int check_interval = 0;
    };

    struct dns_group
    {
        std::string name;
        bool is_default = false;
        std::vector<dns_upstream> upstreams;
    };

    struct dns_rule
    {
        std::string file;
        std::string group;
    };

    struct dns_static
    {
        std::string domain;
        std::string type;
        std::string value;
    };

    struct dns_route
    {
        std::vector<dns_rule> rules;
        std::vector<dns_static> statics;
    };

    class dns_config
    {
    public:
        int max_pools;
        int max_cache;
        std::string listen_address;
        int listen_port;
        std::string log_level;
        std::vector<dns_group> groups;
        std::vector<dns_route> routes;
        std::vector<std::string> check_domains;
    };

    bool load_config(const std::string &config_file, dns_config &config);
}