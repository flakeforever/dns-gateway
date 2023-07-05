//
// File: dns_upstream.cpp
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

#include "dns_upstream.hpp"
#include "dns_log.hpp"
#include "./../lib/CxxUrl/url.hpp"

using asio::awaitable;

namespace dns
{
    dns_upstream::dns_upstream(asio::any_io_executor executor)
        : executor_(std::move(executor))
    {
        host_ = "";
        port_ = 0;
        proxy_type_ = socks::proxy_type::none;
        proxy_host_ = "";
        proxy_port_ = 0;
        check_enabled_ = false;
        check_interval_ = 0;
        last_request_time_ = asio::steady_timer::clock_type::now();
    }

    asio::awaitable<void> dns_upstream::send_request(const char *data, uint16_t data_length, handle_response handler)
    {
        last_request_time_ = asio::steady_timer::clock_type::now();
        co_return;
    }

    void dns_upstream::set_proxy(socks::proxy_type proxy_type, std::string proxy_host, uint16_t proxy_port)
    {
        proxy_type_ = proxy_type;
        proxy_host_ = proxy_host;
        proxy_port_ = proxy_port;
    }

    void dns_upstream::close()
    {
        
    }

    asio::awaitable<void> dns_upstream::execute_handler(handle_response handler, std::error_code error, const char *data, size_t size)
    {
        std::error_code new_ec(error.value(), error.category());

        if (new_ec)
        {
            handle_exception(new_ec);
        }

        if (handler)
        {
            co_await handler(new_ec, data, size);
        }
    }

    asio::awaitable<void> dns_upstream::execute_handler(handle_response handler, std::system_error error, const char *data, size_t size)
    {
        const std::error_code &ec = error.code();
        std::error_code new_ec(ec.value(), ec.category());

        co_await execute_handler(handler, new_ec, data, size);
    }

    asio::awaitable<void> dns_upstream::execute_handler(handle_response handler, dns::errc::error_code error, const char *data, size_t size)
    {
        std::error_code ec = dns::errc::make_error_code(error);
        co_await execute_handler(handler, ec, data, size);
    }

    void dns_upstream::handle_exception(std::error_code error)
    {
    }

    dns_udp_upstream::dns_udp_upstream(asio::any_io_executor executor, std::string host, uint16_t port)
        : dns_upstream(executor),
          client_(executor)
    {
        host_ = host;
        port_ = port;
    }

    asio::awaitable<bool> dns_udp_upstream::associate()
    {
        client_.set_proxy(proxy_type_, proxy_host_, proxy_port_);
        co_return co_await client_.associate(host_, port_);
    }

    void dns_udp_upstream::release()
    {
        client_.release();
    }

    asio::awaitable<void> dns_udp_upstream::send_request(const char *data, uint16_t data_length, handle_response handler)
    {
        try
        {
            await_coroutine_lock lock(executor_, &mutex_);
            co_await lock.check_lock();

            // check associate status
            if (!client_.is_associated())
            {
                co_await associate();
            }

            // send dns request
            last_request_time_ = asio::steady_timer::clock_type::now();
            int length = co_await client_.send(data, data_length);

            if (length != data_length)
            {
                co_await execute_handler(handler, errc::error_code::request_failed);
            }

            length = co_await client_.recv(buffer_, sizeof(buffer_));

            if (length > 0)
            {
                co_await execute_handler(handler, errc::error_code::no_error, buffer_, length);
            }
        }
        catch(const std::exception& e)
        {
            release();
        }
    }

    void dns_udp_upstream::close()
    {
        release();
    }

    dns_https_upstream::dns_https_upstream(asio::any_io_executor executor, std::string url)
        : dns_upstream(executor)
    {
        tls_context_ = new asio::ssl::context(asio::ssl::context::tlsv13_client);
        tls_context_->load_verify_file("/etc/ssl/certs/ca-certificates.crt");

        client_ = std::make_shared<socks::socks_tls_client>(executor, *tls_context_);
        keep_alive_ = false;

        parse_url(url);
    }

    dns_https_upstream::~dns_https_upstream()
    {
        disconnect();

        if (tls_context_)
        {
            delete tls_context_;
        }
    }

    bool dns_https_upstream::is_connected()
    {
        return client_->is_connected();
    }

    asio::awaitable<bool> dns_https_upstream::connect()
    {
        client_->set_proxy(proxy_type_, proxy_host_, proxy_port_);

        logger.info("dns_https_upstream connect");
        bool status = co_await client_->connect(host_, port_);

        co_return status;
    }

    void dns_https_upstream::disconnect()
    {
        logger.info("dns_https_upstream disconnect");
        client_->disconnect();
    }

    char* search_substring(char* buffer, std::size_t buffer_length, const char* substring)
    {
        std::size_t substring_length = std::strlen(substring);

        for (std::size_t i = 0; i < buffer_length; ++i)
        {
            if (i + substring_length > buffer_length)
                break;

            if (std::memcmp(buffer + i, substring, substring_length) == 0)
                return buffer + i;
        }

        return nullptr;
    }

    asio::awaitable<void> dns_https_upstream::send_request(const char *data, uint16_t data_length, handle_response handler)
    {
        try
        {
            await_coroutine_lock lock(executor_, &mutex_);
            co_await lock.check_lock();

            // check connection status
            if (!client_->is_connected())
            {
                co_await connect();
            }

            // send dns request
            last_request_time_ = asio::steady_timer::clock_type::now();
            std::string request = "POST " + path_ + " HTTP/1.1\r\n"
                                "Host: " + host_ + "\r\n"
                                "Content-Type: application/dns-message\r\n"
                                "Connection: keep-alive\r\n"
                                "Content-Length: " + std::to_string(data_length) + "\r\n"
                                "\r\n";

            std::size_t request_length = request.length();
            std::copy(request.begin(), request.end(), buffer_);
            std::copy(data, data + data_length, buffer_ + request_length);
            request_length += data_length;

            co_await client_->write(buffer_, request_length);

            std::string response;
            int buffer_length = co_await client_->get_socket().async_read_some(
                asio::buffer(buffer_, sizeof(buffer_)), asio::use_awaitable);

            char* header_end = search_substring(buffer_, buffer_length, "\r\n\r\n");
            if (header_end != buffer_ + buffer_length)
            {
                // Calculate the length of the data after the header
                header_end += 4;
                int data_length = buffer_length - (header_end - buffer_);

                std::string response_header(buffer_, header_end);
                http_header header = parse_http_header(response_header);
                if (check_http_header(header))
                {
                    if (data_length == header.content_length)
                    {
                        co_await execute_handler(handler, errc::error_code::no_error, header_end, data_length);
                    }
                    else
                    {
                        co_await execute_handler(handler, errc::error_code::http_data_error);
                    }
                }
                else
                {
                    co_await execute_handler(handler, errc::error_code::http_header_invalid);
                }
            }
        }
        catch(const std::exception& e)
        {
            disconnect();
        }
    }

    void dns_https_upstream::close()
    {
        disconnect();
    }

    http_header dns_https_upstream::parse_http_header(const std::string &header_string)
    {
        http_header header;

        size_t start_pos = header_string.find(' ');
        size_t end_pos = header_string.find(' ', start_pos + 1);
        if (start_pos != std::string::npos && end_pos != std::string::npos)
        {
            header.http_version = header_string.substr(0, start_pos);
            header.status_code = std::stoi(header_string.substr(start_pos + 1, end_pos - start_pos - 1));
            header.status_message = header_string.substr(end_pos + 1, header_string.find('\n', end_pos) - end_pos - 1);
        }

        size_t pos = header_string.find('\n');
        while (pos != std::string::npos && pos < header_string.length() - 1)
        {
            size_t separator_pos = header_string.find(':', pos);
            if (separator_pos != std::string::npos)
            {
                std::string key = header_string.substr(pos + 1, separator_pos - pos - 1);
                std::string value = header_string.substr(separator_pos + 2, header_string.find('\n', separator_pos) - separator_pos - 2);

                if (!value.empty() && value.back() == '\r')
                {
                    value.pop_back();
                }

                // Convert the key to lowercase for case-insensitive comparison
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);

                if (key == "server")
                {
                    header.server = value;
                }
                else if (key == "date")
                {
                    header.date = value;
                }
                else if (key == "content-type")
                {
                    header.content_type = value;
                }
                else if (key == "connection")
                {
                    header.connection = value;
                }
                else if (key == "content-length")
                {
                    header.content_length = std::stoi(value);
                }
            }

            pos = header_string.find('\n', pos + 1);
        }

        return header;
    }

    bool dns_https_upstream::check_http_header(http_header header)
    {
        if (header.status_code != 200)
        {
            return false;
        }

        if (header.content_type != "application/dns-message")
        {
            return false;
        }

        // ignore kee-alive
        // if (header.connection != "keep-alive")
        // {
        //     return false;
        // }

        if (header.content_length == 0)
        {
            return false;
        }

        return true;
    }

    void dns_https_upstream::handle_exception(std::error_code error)
    {
        if (error)
        {
            disconnect();
        }
    }

    void dns_https_upstream::parse_url(std::string url)
    {
        Url upstream_url(url);

        scheme_ = upstream_url.scheme();
        path_ = upstream_url.path();

        host_ = upstream_url.host();
        if (upstream_url.port() == "" && scheme_ == "doh")
        {
            port_ = dns::doh_port;
        }
        else
        {
            port_ = std::stoi(upstream_url.port());
        }
    }
}