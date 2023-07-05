//
// File: dns_object.hpp
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

#include <asio.hpp>
#include <vector>
#include <mutex>
#include <algorithm>
#include "dns_package.hpp"

namespace dns
{
    class dns_object
    {
    public:
        enum class object_type
        {
            static_object,
            dynamic_object
        };

        dns_object();
        ~dns_object();

        object_type type_;

        // dns raw data
        char buffer_[dns::buffer_size];
        int buffer_length_;
        asio::ip::udp::endpoint remote_endpoint_;

        // dns question
        uint16_t question_id_;
        std::string question_domain_;
        uint8_t question_type_;
    };

    class dns_object_pool
    {
    public:
        dns_object_pool(asio::any_io_executor executor, int min_pools, int max_pool);

        asio::awaitable<dns_object *> get_object();
        asio::awaitable<void> release_object(dns_object *object);

    private:
        void init_object(int min_pools);

        asio::any_io_executor executor_;
        std::mutex mutex_;
        std::vector<dns_object *> static_objects_;
        std::vector<dns_object *> active_objects_;

        size_t min_pools_;
        size_t max_pool_;
    };
}