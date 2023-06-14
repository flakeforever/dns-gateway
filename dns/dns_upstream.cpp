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
#include "base64.hpp"
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

    asio::awaitable<void> dns_upstream::wait_until_lock(std::unique_lock<std::mutex> &lock, std::chrono::milliseconds duration)
    {
        if (!lock.owns_lock())
        {
            async_wait async_wait(executor_);
            co_await async_wait.wait_until(
                duration,
                [&](bool &finished)
                {
                    lock.try_lock();
                    if (lock.owns_lock())
                    {
                        finished = true;
                    }
                });
        }
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
        std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
        co_await wait_until_lock(lock, std::chrono::milliseconds(10));

        // check associate status
        if (!client_.is_associated())
        {
            async_execute execute(executor_);
            co_await execute.execute_until(
                std::chrono::milliseconds(connect_timeout),
                [&](asio::steady_timer &timer) -> asio::awaitable<void>
                {
                    try
                    {
                        co_await associate();
                    }
                    catch (const std::system_error &e)
                    {
                        if (execute.timeout())
                        {
                            co_await execute_handler(handler, errc::error_code::request_timeout);
                        }
                        else
                        {
                            co_await execute_handler(handler, e);
                        }
                    }
                    catch (const std::exception &e)
                    {
                        co_await execute_handler(handler, errc::error_code::unknown_error);
                    }

                    timer.cancel();
                });
        }

        // send dns request
        last_request_time_ = asio::steady_timer::clock_type::now();
        async_execute execute(executor_);
        co_await execute.execute_until(
            std::chrono::milliseconds(request_timeout),
            [&](asio::steady_timer &timer) -> asio::awaitable<void>
            {
                try
                {
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
                catch (const std::system_error &e)
                {
                    if (execute.timeout())
                    {
                        co_await execute_handler(handler, errc::error_code::request_timeout);
                    }
                    else
                    {
                        co_await execute_handler(handler, e);
                    }
                }
                catch (const std::exception &e)
                {
                    co_await execute_handler(handler, errc::error_code::unknown_error);
                }

                timer.cancel();
            });
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
        bool status = co_await client_->connect(host_, port_);

        co_return status;
    }

    void dns_https_upstream::disconnect()
    {
        client_->disconnect();
    }

    asio::awaitable<void> dns_https_upstream::send_request(const char *data, uint16_t data_length, handle_response handler)
    {
        std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
        co_await wait_until_lock(lock, std::chrono::milliseconds(10));

        // check connection status
        if (!client_->is_connected())
        {
            async_execute execute(executor_);
            co_await execute.execute_until(
                std::chrono::milliseconds(connect_timeout),
                [&](asio::steady_timer &timer) -> asio::awaitable<void>
                {
                    try
                    {
                        co_await connect();
                    }
                    catch (const std::system_error &e)
                    {
                        if (execute.timeout())
                        {
                            co_await execute_handler(handler, errc::error_code::request_timeout);
                        }
                        else
                        {
                            co_await execute_handler(handler, e);
                        }
                    }
                    catch (const std::exception &e)
                    {
                        co_await execute_handler(handler, errc::error_code::unknown_error);
                    }

                    timer.cancel();
                });
        }

        // send dns request
        last_request_time_ = asio::steady_timer::clock_type::now();
        async_execute execute(executor_);
        co_await execute.execute_until(
            std::chrono::milliseconds(request_timeout),
            [&](asio::steady_timer &timer) -> asio::awaitable<void>
            {
                try
                {
                    // dns request
                    if (logger.level() == dns::log_level::debug)
                    {
                        std::string base64_request = base64::encode(data, data_length);
                        logger.debug("request: %s", base64_request.c_str());
                    }

                    std::string request = "POST " + path_ + " HTTP/1.1\r\n"
                                          "Host: " + host_ + "\r\n"
                                          "Content-Type: application/dns-message\r\n"
                                          "Connection: keep-alive\r\n"
                                          "Content-Length: " + std::to_string(data_length) + "\r\n"
                                          "\r\n";

                    co_await client_->write(request.c_str(), request.length());
                    co_await client_->write(data, data_length);

                    std::string response;
                    int header_length = co_await asio::async_read_until(
                        client_->get_socket(), asio::dynamic_buffer(response, 1024), "\r\n\r\n", asio::use_awaitable);

                    // char header_str[1024];
                    // memset(header_str, 0, sizeof(header_str));
                    // response.copy(header_str, header_length, 0);
                    // std::cerr << "header: " << header_str << std::endl;

                    http_header header = parse_http_header(response);
                    if (check_http_header(header))
                    {
                        if (logger.level() == dns::log_level::debug)
                        {
                            logger.debug("response: %s", header.http_version.c_str());
                            logger.debug("HTTP status:  %d", header.status_code);
                            logger.debug("Date: %s", header.date.c_str());
                        }

                        int remaining_length = response.size() - header_length;
                        if (header.content_length > remaining_length)
                        {
                            if (header.content_length > dns::buffer_size)
                            {
                                co_await execute_handler(handler, errc::error_code::buffer_not_enough);
                            }
                            else
                            {
                                response.copy(buffer_, remaining_length, header_length);

                                int length = co_await client_->read(buffer_ + remaining_length, header.content_length - remaining_length);

                                if (length == header.content_length - remaining_length)
                                {
                                    co_await execute_handler(handler, errc::error_code::no_error, buffer_, header.content_length);
                                }
                                else
                                {
                                    co_await execute_handler(handler, errc::error_code::http_data_error);
                                }
                            }
                        }
                        else if (header.content_length == remaining_length)
                        {
                            response.copy(buffer_, header.content_length, header_length);
                            co_await execute_handler(handler, errc::error_code::no_error, buffer_, header.content_length);
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
                catch (const std::system_error &e)
                {
                    if (execute.timeout())
                    {
                        co_await execute_handler(handler, errc::error_code::request_timeout);
                    }
                    else
                    {
                        co_await execute_handler(handler, e);
                    }
                }
                catch (const std::exception &e)
                {
                    co_await execute_handler(handler, errc::error_code::unknown_error);
                }

                timer.cancel();
            });
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