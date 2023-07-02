//
// File: config.cpp
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

#include "config.hpp"
#include "lib/picojson/picojson.h"
#include <sstream>

namespace config
{
    bool load_config(const std::string &config_file, dns_config &config)
    {
        std::ifstream ifs(config_file);
        if (!ifs.is_open())
        {
            std::cout << "Failed to open config file: " << config_file << std::endl;
            return false;
        }

        // Read the entire contents of the file into a string
        std::string json_str((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

        // Parse the JSON string
        picojson::value json;
        std::string err = picojson::parse(json, json_str);
        if (!err.empty())
        {
            std::cout << "Failed to parse JSON: " << err << std::endl;
            return false;
        }

        // Extract the values from the JSON and populate the config object
        if (!json.is<picojson::object>())
        {
            std::cout << "Invalid JSON format: expected an object" << std::endl;
            return false;
        }

        picojson::object &obj = json.get<picojson::object>();
        if (obj.find("max_works") != obj.end() && obj["max_works"].is<double>())
        {
            config.max_works = static_cast<int>(obj["max_works"].get<double>());

            if (config.max_works <= 0)
            {
                std::cout << "Invalid config format: max_works cannot be set to \""
                          << config.max_works << "\"." << std::endl;
                return false;
            }
        }
        if (obj.find("min_pools") != obj.end() && obj["min_pools"].is<double>())
        {
            config.min_pools = static_cast<int>(obj["min_pools"].get<double>());
        }
        if (obj.find("max_pools") != obj.end() && obj["max_pools"].is<double>())
        {
            config.max_pools = static_cast<int>(obj["max_pools"].get<double>());
        }
        if (obj.find("max_cache") != obj.end() && obj["max_cache"].is<double>())
        {
            config.max_cache = static_cast<int>(obj["max_cache"].get<double>());
        }
        if (obj.find("protocol") != obj.end() && obj["protocol"].is<std::string>())
        {
            config.protocol = obj["protocol"].get<std::string>();
        }
        if (obj.find("listen_address") != obj.end() && obj["listen_address"].is<std::string>())
        {
            config.listen_address = obj["listen_address"].get<std::string>();
        }
        if (obj.find("listen_port") != obj.end() && obj["listen_port"].is<double>())
        {
            config.listen_port = static_cast<int>(obj["listen_port"].get<double>());
        }
        if (obj.find("log_level") != obj.end() && obj["log_level"].is<std::string>())
        {
            config.log_level = obj["log_level"].get<std::string>();
        }
        if (obj.find("groups") != obj.end() && obj["groups"].is<picojson::array>())
        {
            const picojson::array &groups_arr = obj["groups"].get<picojson::array>();
            for (const auto &group_val : groups_arr)
            {
                if (group_val.is<picojson::object>())
                {
                    picojson::object group_obj(group_val.get<picojson::object>());
                    dns_group group;
                    if (group_obj.find("name") != group_obj.end() && group_obj["name"].is<std::string>())
                    {
                        group.name = group_obj["name"].get<std::string>();
                    }
                    if (group_obj.find("default") != group_obj.end() && group_obj["default"].is<bool>())
                    {
                        group.is_default = group_obj["default"].get<bool>();
                    }
                    if (group_obj.find("upstreams") != group_obj.end() && group_obj["upstreams"].is<picojson::array>())
                    {
                        picojson::array &upstreams_arr = group_obj["upstreams"].get<picojson::array>();
                        for (const auto &upstream_val : upstreams_arr)
                        {
                            if (upstream_val.is<picojson::object>())
                            {
                                picojson::object upstream_obj(upstream_val.get<picojson::object>());
                                dns_upstream upstream;
                                if (upstream_obj.find("uri") != upstream_obj.end() && upstream_obj["uri"].is<std::string>())
                                {
                                    upstream.uri = upstream_obj["uri"].get<std::string>();
                                }
                                if (upstream_obj.find("proxy") != upstream_obj.end() && upstream_obj["proxy"].is<std::string>())
                                {
                                    upstream.proxy = upstream_obj["proxy"].get<std::string>();
                                }
                                if (upstream_obj.find("keep_alive") != upstream_obj.end() && upstream_obj["keep_alive"].is<bool>())
                                {
                                    upstream.keep_alive = upstream_obj["keep_alive"].get<bool>();
                                }
                                if (upstream_obj.find("check_enabled") != upstream_obj.end() && upstream_obj["check_enabled"].is<bool>())
                                {
                                    upstream.check_enabled = upstream_obj["check_enabled"].get<bool>();
                                }
                                if (upstream_obj.find("check_interval") != upstream_obj.end() && upstream_obj["check_interval"].is<double>())
                                {
                                    upstream.check_interval = static_cast<int>(upstream_obj["check_interval"].get<double>());
                                }
                                group.upstreams.push_back(upstream);
                            }
                        }
                    }
                    config.groups.push_back(group);
                }
            }
        }
        if (obj.find("routes") != obj.end() && obj["routes"].is<picojson::array>())
        {
            const picojson::array &routes_arr = obj["routes"].get<picojson::array>();
            for (const auto &route_val : routes_arr)
            {
                if (route_val.is<picojson::object>())
                {
                    picojson::object route_obj(route_val.get<picojson::object>());
                    dns_route route;
                    if (route_obj.find("rules") != route_obj.end() && route_obj["rules"].is<picojson::array>())
                    {
                        const picojson::array &rules_arr = route_obj["rules"].get<picojson::array>();
                        for (const auto &rule_val : rules_arr)
                        {
                            if (rule_val.is<picojson::object>())
                            {
                                picojson::object rule_obj(rule_val.get<picojson::object>());
                                dns_rule rule;
                                if (rule_obj.find("file") != rule_obj.end() && rule_obj["file"].is<std::string>())
                                {
                                    rule.file = rule_obj["file"].get<std::string>();
                                }
                                if (rule_obj.find("group") != rule_obj.end() && rule_obj["group"].is<std::string>())
                                {
                                    rule.group = rule_obj["group"].get<std::string>();
                                }
                                route.rules.push_back(rule);
                            }
                        }
                    }
                    if (route_obj.find("statics") != route_obj.end() && route_obj["statics"].is<picojson::array>())
                    {
                        const picojson::array &statics_arr = route_obj["statics"].get<picojson::array>();
                        for (const auto &static_val : statics_arr)
                        {
                            if (static_val.is<picojson::object>())
                            {
                                picojson::object static_obj(static_val.get<picojson::object>());
                                dns_static static_entry;
                                if (static_obj.find("domain") != static_obj.end() && static_obj["domain"].is<std::string>())
                                {
                                    static_entry.domain = static_obj["domain"].get<std::string>();
                                }
                                if (static_obj.find("type") != static_obj.end() && static_obj["type"].is<std::string>())
                                {
                                    static_entry.type = static_obj["type"].get<std::string>();
                                }
                                if (static_obj.find("value") != static_obj.end() && static_obj["value"].is<std::string>())
                                {
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
        if (obj.find("check_domains") != obj.end() && obj["check_domains"].is<std::string>())
        {
            std::string test_domains_str = obj["check_domains"].get<std::string>();
            std::stringstream ss(test_domains_str);
            std::string domain;
            while (std::getline(ss, domain, ','))
            {
                // Remove leading and trailing spaces
                size_t start = domain.find_first_not_of(' ');
                size_t end = domain.find_last_not_of(' ');
                if (start != std::string::npos && end != std::string::npos)
                {
                    domain = domain.substr(start, end - start + 1);
                    config.check_domains.push_back(domain);
                }
            }
        }

        return true;
    }
}