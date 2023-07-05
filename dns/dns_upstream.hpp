//
// File: dns_upstream.hpp
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
#include "socks/socks_client.hpp"
#include "dns_buffer.hpp"
#include "dns_error.hpp"
#include "operation.hpp"
#include "property.hpp"
#include <mutex>

namespace dns
{
    constexpr int connect_timeout = 15000;
    constexpr int request_timeout = 3500;
    constexpr int doh_port = 443;
    constexpr int dot_port = 853;

    class dns_upstream_property
    {
    public:
        PROPERTY_READONLY(std::string, host);
        PROPERTY_READONLY(uint16_t, port);
        PROPERTY_READONLY(socks::proxy_type, proxy_type);
        PROPERTY_READONLY(std::string, proxy_host);
        PROPERTY_READONLY(uint16_t, proxy_port);

        PROPERTY_READWRITE(bool, check_enabled);
        PROPERTY_READWRITE(int, check_interval);

        PROPERTY_READONLY(asio::steady_timer::time_point, last_request_time);
    };

    class dns_upstream : public dns_upstream_property, public std::enable_shared_from_this<dns_upstream>
    {
    public:
        typedef std::function<asio::awaitable<void>(std::error_code ec, const char *data, uint16_t data_length)> handle_response;

        dns_upstream(asio::any_io_executor executor);

        virtual asio::awaitable<void> send_request(const char *data, uint16_t data_length, handle_response handler);
        virtual void set_proxy(socks::proxy_type proxy_type, std::string proxy_host, uint16_t proxy_port);
        virtual void close();

    protected:
        asio::awaitable<void> execute_handler(handle_response handler, std::error_code error, const char *data = nullptr, size_t size = 0);
        asio::awaitable<void> execute_handler(handle_response handler, std::system_error error, const char *data = nullptr, size_t size = 0);
        asio::awaitable<void> execute_handler(handle_response handler, dns::errc::error_code error, const char *data = nullptr, size_t size = 0);
        virtual void handle_exception(std::error_code error);
        
        asio::any_io_executor executor_;
        coroutine_mutex mutex_;
        char buffer_[dns::buffer_size];

    private:
    };

    class dns_udp_upstream : public dns_upstream
    {
    public:
        dns_udp_upstream(asio::any_io_executor executor, std::string host, uint16_t port);

        asio::awaitable<void> send_request(const char *data, uint16_t data_length, handle_response handler) override;
        void close() override;

    protected:
        asio::awaitable<bool> associate();
        void release();

    private:
        socks::socks_udp_client client_;
    };

    class http_header
    {
    public:
        std::string http_version;
        int status_code;
        std::string status_message;
        std::string server;
        std::string date;
        std::string content_type;
        std::string connection;
        int content_length;
    };

    class dns_https_upstream_property
    {
        PROPERTY_READWRITE(bool, keep_alive);
    };

    class dns_https_upstream : public dns_https_upstream_property, public dns_upstream
    {
    public:
        dns_https_upstream(asio::any_io_executor executor, std::string url);
        ~dns_https_upstream();

        asio::awaitable<void> send_request(const char *data, uint16_t data_length, handle_response handler) override;
        void close() override;

    protected:
        asio::awaitable<bool> connect();
        void disconnect();
        bool is_connected();

        void parse_url(std::string url);
        http_header parse_http_header(const std::string &header_string);
        bool check_http_header(http_header header);
        void handle_exception(std::error_code error) override;

    private:
        asio::ssl::context *tls_context_;
        std::shared_ptr<socks::socks_tls_client> client_;

        std::string scheme_;
        std::string path_;
        char buffer_[dns::buffer_size];
    };
}