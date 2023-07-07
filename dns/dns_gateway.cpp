//
// File: dns_gateway.cpp
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

#include <thread>
#include "dns_gateway.hpp"
#include "dns_buffer.hpp"
#include "dns_cache.hpp"
#include "dns_package.hpp"

namespace dns
{
    dns_gateway::dns_gateway(asio::any_io_executor executor,
                             asio::ip::udp::resolver::protocol_type protocol, uint16_t port,
                             int min_pools, int max_pools)
        : executor_(executor),
          port_(port),
          udp_socket_(executor, asio::ip::udp::endpoint(protocol, port)),
          object_pool_(executor, min_pools, max_pools),
          router_(executor),
          cache_(executor)
    {
    }

    dns_gateway::dns_gateway(asio::any_io_executor executor,
                             std::string address, uint16_t port,
                             int min_pools, int max_pools)
        : executor_(executor),
          port_(port),
          udp_socket_(executor, asio::ip::udp::endpoint(asio::ip::make_address(address), port)),
          object_pool_(executor, min_pools, max_pools),
          router_(executor),
          cache_(executor)
    {
    }

    std::string endpoint_to_string(const asio::ip::udp::endpoint &endpoint)
    {
        std::string address = endpoint.address().to_string();
        unsigned short port = endpoint.port();

        return address + ":" + std::to_string(port);
    }

    asio::awaitable<void> dns_gateway::run_process()
    {
        active_ = true;
        while (active_)
        {
            try
            {
                // receive data from udp listening
                int length = co_await do_receive();

                if (length <= 0)
                {
                    logger.error("length error");
                    continue;
                }

                dns::dns_package package;
                try
                {
                    package.parse(buffer_, length);
                }
                catch (const std::exception &e)
                {
                    logger.error("DNS exception occured when parsing incoming data");
                    continue;
                }

                if (package.flag_qr() != 0 || package.que_count() == 0 || package.ans_count() > 0)
                {
                    continue;
                }

                // get a dns object from queue
                dns::dns_object *dns_object = co_await object_pool_.get_object();
                if (dns_object == nullptr)
                {
                    logger.error("dns_object is null");
                    continue;
                }

                // init dns object
                memset(dns_object->buffer_, 0, sizeof(dns_object->buffer_));
                memcpy(dns_object->buffer_, buffer_, length);
                dns_object->buffer_length_ = length;

                dns_object->question_id_ = package.id();
                dns_object->question_domain_ = package.questions_[0]->q_name();
                dns_object->question_type_ = package.questions_[0]->q_type();
                dns_object->remote_endpoint_ = remote_endpoint_;

                logger.debug("request %d %s type %d from %s",
                             dns_object->question_id_, dns_object->question_domain_.c_str(), dns_object->question_type_,
                             endpoint_to_string(dns_object->remote_endpoint_).c_str());

                // define a coroutine for request
                auto request_coroutine = [&](dns::dns_object *new_object) -> asio::awaitable<void>
                {
                    // // handle dns static
                    // bool status = co_await handle_dns_static(new_object, request_domain, request_type);
                    // if (status)
                    // {
                    //     co_await object_pool_.release_object(new_object);
                    //     timer.cancel();
                    //     co_return;
                    // }

                    // handle dns cache
                    bool status = co_await handle_query_cache(new_object);
                    if (!status)
                    {
                        // handle dns request
                        co_await handle_dns_request(new_object);
                    }

                    co_await object_pool_.release_object(new_object);
                    co_return;
                };

                // create a new coroutine for request
                co_spawn(executor_, request_coroutine(dns_object), detached);
            }
            catch (const std::exception &e)
            {
                logger.error("process error: %s", e.what());
                break;
            }
        }

        terminated_ = true;
        co_return;
    }

    dns_router &dns_gateway::get_router()
    {
        return router_;
    }

    dns_cache &dns_gateway::get_cache()
    {
        return cache_;
    }

    asio::any_io_executor dns_gateway::get_executor()
    {
        return executor_;
    }

    void dns_gateway::set_active(const bool &value)
    {
        active_ = value;

        if (!active_)
        {
            if (udp_socket_.is_open())
            {
                udp_socket_.close();
            }
        }
        else
        {
            start_checker();
        }
    }

    asio::awaitable<bool> dns_gateway::handle_dns_static(
        std::shared_ptr<dns::dns_object> dns_object, std::string request_domain, dns::anwser_type request_type)
    {
        // if (dns_object->dns_package_.questions_.size() == 1)
        // {
        //     // check domain static
        //     std::vector<std::string> static_values = router_.get_statics().get_static_values(request_domain, request_type);

        //     if (static_values.size() > 0)
        //     {
        //         for (auto value : static_values)
        //         {
        //             dns_object->dns_package_.add_anwser(request_domain, request_type, value);
        //         }

        //         //  Forward the response to the client
        //         dns_object->buffer_length_ =
        //             dns_object->dns_package_.dump(dns_object->buffer_, sizeof(dns_object->buffer_));

        //         co_await udp_socket_.async_send_to(
        //             asio::buffer(dns_object->buffer_, dns_object->buffer_length_),
        //             dns_object->remote_endpoint_,
        //             asio::use_awaitable);

        //         co_return true;
        //     }
        // }

        co_return false;
    }

    asio::awaitable<bool> dns_gateway::handle_create_cache(dns::dns_object *dns_object)
    {
        dns::dns_package package;
        try
        {
            package.parse(dns_object->buffer_, dns_object->buffer_length_);
        }
        catch (const std::exception &e)
        {
            co_return false;
        }

        if (package.flag_qr() != static_cast<uint8_t>(dns::qr_type::response) ||
            package.flag_rcode() != static_cast<uint8_t>(dns::rcode_type::ok_response) ||
            package.que_count() > 1 ||
            package.ans_count() == 0)
        {
            co_return false;
        }

        await_coroutine_lock lock(executor_, &cache_.mutex_);
        co_await lock.check_lock();

        dns_cache_entry *cache_entry = co_await cache_.get_free_cache();
        if (cache_entry != nullptr)
        {
            cache_entry->domain_ = dns_object->question_domain_;
            cache_entry->create_time_ = dns::get_current_time();
            cache_entry->set_ttl(package.get_ttl());

            memcpy(cache_entry->buffer_, dns_object->buffer_, dns_object->buffer_length_);
            cache_entry->buffer_size_ = dns_object->buffer_length_;

            co_await cache_.add_cache(dns_object->question_domain_, dns_object->question_type_, cache_entry);
            co_return true;
        }

        co_return false;
    }

    asio::awaitable<bool> dns_gateway::handle_query_cache(dns::dns_object *dns_object)
    {
        bool status = false;

        {
            await_coroutine_lock lock(executor_, &cache_.mutex_);
            co_await lock.check_lock();

            dns_cache_entry *cache_entry =
                co_await cache_.query_cache(dns_object->question_domain_, dns_object->question_type_);
            if (cache_entry != nullptr)
            {
                dns::dns_package package;

                try
                {
                    status = package.parse(cache_entry->buffer_, cache_entry->buffer_size_);
                }
                catch (const std::exception &e)
                {
                }

                if (status)
                {
                    package.id(dns_object->question_id_);
                    package.set_ttl(cache_entry->get_ttl());

                    try
                    {
                        dns_object->buffer_length_ = package.dump(dns_object->buffer_, sizeof(dns_object->buffer_));
                    }
                    catch (const std::exception &e)
                    {
                        logger.error("package dump error: %s", e.what());
                        status = false;
                    }

                    if (dns_object->buffer_length_ == 0)
                    {
                        logger.error("package dump: buffer_length_ == 0");
                        status = false;
                    }
                }
            }
        }

        if (status)
        {
            co_await udp_socket_.async_send_to(
                asio::buffer(dns_object->buffer_, dns_object->buffer_length_),
                dns_object->remote_endpoint_,
                asio::use_awaitable);
            co_return true;
        }

        co_return false;
    }

    asio::awaitable<bool> dns_gateway::handle_dns_request(dns::dns_object *dns_object)
    {
        bool result = false;

        // get an upstream group by domain
        std::shared_ptr<dns_upstream_group> current_group = router_.default_group;
        uint8_t group_id = co_await router_.get_route(dns_object->question_domain_);
        std::shared_ptr<dns::dns_upstream_group> upstream_group = router_.get_group(group_id);

        if (upstream_group)
        {
            current_group = upstream_group;
            dns::logger.debug("route : %s -> %s", dns_object->question_domain_.c_str(), upstream_group->name().c_str());
        }
        else
        {
            dns::logger.debug("default route : %s -> %s",
                              dns_object->question_domain_.c_str(), router_.default_group->name().c_str());
        }

        // get an upstream
        std::shared_ptr<dns_upstream> dns_upstream = co_await current_group->get_next_upstream();

        if (dns_upstream == nullptr)
        {
            dns::logger.error("dns_upstream is null");
            co_return false;
        }

        // define a handle for response
        bool status = false;
        auto handle_response = [&](std::error_code ec, const char *data, uint16_t data_length) -> asio::awaitable<void>
        {
            if (!ec)
            {
                if (data_length > dns::buffer_size)
                {
                    co_return;
                }

                // update dns cache
                memcpy(dns_object->buffer_, data, data_length);
                dns_object->buffer_length_ = data_length;

                status = true;
            }
            else
            {
                logger.error("error: %d message: %s", ec.value(), ec.message().c_str());
                status = false;
            }

            co_return;
        };

        await_timeout_execute timeout_execute(executor_);
        co_await timeout_execute.execute_until(
            std::chrono::milliseconds(dns::coroutine_timeout),
            [&](asio::steady_timer &timer) -> asio::awaitable<void>
            {
                try
                {
                    await_coroutine_lock lock(executor_, &dns_upstream->mutex_);
                    co_await lock.check_lock();

                    bool status = co_await dns_upstream->is_open();
                    if (!status)
                    {
                        status = co_await dns_upstream->open();
                    }

                    if (status)
                    {
                        logger.info("request %d %s type %d to %s:%d",
                                    dns_object->question_id_, dns_object->question_domain_.c_str(), dns_object->question_type_,
                                    dns_upstream->host().c_str(), dns_upstream->port());

                        status = co_await dns_upstream->send_request(
                            dns_object->buffer_, dns_object->buffer_length_, handle_response);

                        if (!status)
                        {
                            co_await dns_upstream->close();
                        }
                    }
                    else
                    {
                        logger.error("dns_upstream is closed");
                    }
                }
                catch (const std::exception &e)
                {
                    
                    logger.error("request error: %s", e.what());
                }

                if (!timeout_execute.timeout())
                {
                    timer.cancel();
                }
            });

        if (status)
        {
            dns::dns_package package;
            try
            {
                status = package.parse(dns_object->buffer_, dns_object->buffer_length_);
                if (package.id() != dns_object->question_id_)
                {
                    package.output();
                }
            }
            catch (const std::exception &e)
            {
            }

            if (status)
            {
                // update dns cache
                co_await handle_create_cache(dns_object);

                logger.debug("response %d %s type %d to %s",
                             dns_object->question_id_, dns_object->question_domain_.c_str(),
                             dns_object->question_type_,
                             endpoint_to_string(dns_object->remote_endpoint_).c_str());

                dns_object->buffer_length_ =
                    package.dump(dns_object->buffer_, sizeof(dns_object->buffer_));
            }

            co_await udp_socket_.async_send_to(
                asio::buffer(dns_object->buffer_, dns_object->buffer_length_),
                dns_object->remote_endpoint_, asio::use_awaitable);

            result = true;
        }

        co_return result;
    }

    asio::awaitable<void> dns_gateway::wait_terminated()
    {
        await_wait wait(executor_);
        co_await wait.wait_until(
            std::chrono::milliseconds(10),
            [&](bool &finished)
            {
                if (terminated_ && !checker_started_)
                {
                    finished = true;
                }
            });
    }

    asio::awaitable<int> dns_gateway::do_receive()
    {
        memset(buffer_, 0, sizeof(buffer_));
        co_return co_await udp_socket_.async_receive_from(asio::buffer(buffer_), remote_endpoint_, asio::use_awaitable);
    }

    void dns_gateway::start_checker()
    {
        if (!check_domains.size())
        {
            logger.error("handle_check failed : check_domains is null");
            return;
        }

        auto handle_check = [&]() -> asio::awaitable<void>
        {
            int domain_index = 0;
            char buffer[dns::buffer_size];

            checker_started_ = true;
            while (active_)
            {
                try
                {
                    std::string domain = check_domains[domain_index];
                    domain_index = (domain_index + 1) % check_domains.size();

                    for (const auto &dns_upstream : upstreams_)
                    {
                        if (dns_upstream->check_enabled())
                        {
                            asio::steady_timer::time_point now = asio::steady_timer::clock_type::now();
                            std::chrono::milliseconds time_diff =
                                std::chrono::duration_cast<std::chrono::seconds>(now - dns_upstream->last_request_time());

                            if (time_diff >= std::chrono::seconds(dns_upstream->check_interval()))
                            {
                                dns_package package;
                                package.add_question(domain, dns::anwser_type::a);
                                int length = package.dump(buffer, sizeof(buffer));

                                // define a handle for response
                                auto handle_response =
                                    [&](std::error_code ec, const char *data, uint16_t data_length) -> asio::awaitable<void>
                                {
                                    if (ec)
                                    {
                                        logger.error("check error: %d message: %s", ec.value(), ec.message().c_str());
                                    }

                                    co_return;
                                };

                                await_timeout_execute timeout_execute(executor_);
                                co_await timeout_execute.execute_until(
                                    std::chrono::milliseconds(dns::coroutine_timeout),
                                    [&](asio::steady_timer &timer) -> asio::awaitable<void>
                                    {
                                        try
                                        {
                                            await_coroutine_lock lock(executor_, &dns_upstream->mutex_);
                                            co_await lock.check_lock();

                                            bool status = co_await dns_upstream->is_open();
                                            if (!status)
                                            {
                                                status = co_await dns_upstream->open();
                                            }

                                            if (status)
                                            {
                                                status = co_await dns_upstream->send_request(buffer, length, handle_response);

                                                if (!status)
                                                {
                                                    co_await dns_upstream->close();
                                                }
                                            }
                                        }
                                        catch (const std::exception &e)
                                        {
                                            logger.error("check error: %s", e.what());
                                        }

                                        if (!timeout_execute.timeout())
                                        {
                                            timer.cancel();
                                        }
                                    });
                            }
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    logger.error("handle_check failed : %s", e.what());
                }

                asio::steady_timer timer(executor_, std::chrono::milliseconds(250));
                co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
            }

            checker_started_ = false;
            co_return;
        };

        co_spawn(executor_, handle_check, detached);
    }
}
