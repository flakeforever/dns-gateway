//
// File: dns_gateway.hpp
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
#include <vector>
#include "dns_cache.hpp"
#include "dns_log.hpp"
#include "dns_package.hpp"
#include "dns_router.hpp"
#include "dns_upstream.hpp"
#include "operation.hpp"
#include "property.hpp"

namespace dns
{
    constexpr int dns_port = 53;

    class dns_object : public semaphore_object
    {
    public:
        asio::ip::udp::endpoint remote_endpoint_;
        dns::dns_package dns_package_;
        char buffer_[dns::buffer_size];
        int buffer_length_;
    };

    class dns_gateway_propery
    {
    public:
        PROPERTY_READWRITE(bool, active);
        PROPERTY_READONLY(bool, terminated);
        PROPERTY_READONLY(bool, checker_started);
    };

    class dns_gateway : public dns_gateway_propery
    {
    public:
        dns_gateway(asio::any_io_executor executor, std::string address, uint16_t port, int max_works);

        asio::awaitable<void> run_process();

        dns_router &get_router();
        dns_cache &get_cache();

        asio::awaitable<void> wait_terminated();
        asio::any_io_executor get_executor();

        std::vector<std::shared_ptr<dns_upstream>> upstreams_;
        std::vector<std::string> check_domains;

    protected:
        void init_semaphore(int max_works);
        void start_checker();
        asio::awaitable<int> do_receive();
        void set_active(const bool &value) override;
        asio::awaitable<bool> handle_dns_static(
            std::shared_ptr<dns::dns_object> dns_object, std::string request_domain, dns::anwser_type request_type);
        asio::awaitable<bool> handle_query_cache(
            std::shared_ptr<dns::dns_object> dns_object, std::string request_domain, dns::anwser_type request_type);
        bool handle_create_cache(
            std::shared_ptr<dns::dns_object> dns_object, std::string request_domain, dns::anwser_type request_type);
        asio::awaitable<bool> handle_dns_request(
            std::shared_ptr<dns::dns_object> dns_object, std::string request_domain, dns::anwser_type request_type);
    private:
        asio::any_io_executor executor_;
        uint16_t port_;
        asio::ip::udp::socket udp_socket_;
        semaphore semaphore_;
        asio::ip::udp::endpoint remote_endpoint_;

        dns_router router_;
        dns_cache cache_;
        char buffer_[dns::buffer_size];
    };
}
