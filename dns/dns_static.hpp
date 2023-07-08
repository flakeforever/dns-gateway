//
// File: dns_static.hpp
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

#include <string>
#include <vector>
#include "dns_package.hpp"
#include "operation.hpp"

namespace dns
{
    class dns_statics
    {
    public:
        dns_statics(asio::any_io_executor executor);

        void add_static_value(
            const std::string &domain, dns::anwser_type type, const std::string &value);
        asio::awaitable<std::vector<std::string>> get_static_values(
            const std::string &domain, dns::anwser_type type);

        std::atomic_bool locked_ = false;
        
    private:
        std::string generate_key(const std::string &domain, dns::anwser_type type);

        std::map<std::string, std::vector<std::string>> static_values_;

        asio::any_io_executor executor_;
    };
}